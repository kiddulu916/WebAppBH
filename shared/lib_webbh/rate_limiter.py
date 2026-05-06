"""Centralized sliding-window rate limiter backed by Redis.

All workers should call ``acquire()`` or ``wait_and_acquire()`` before making
HTTP requests to a target domain, preventing accidental DoS and WAF bans.

Supports stackable rate rules via the ``RateLimiter`` class, which accepts
multiple ``RateRule`` instances (parsed from JSON via ``parse_rate_rule``).
"""
from __future__ import annotations

import asyncio
import os
import re as _re
import time
from dataclasses import dataclass

from lib_webbh.messaging import get_redis

DEFAULT_RATE_LIMIT = int(os.environ.get("DEFAULT_RATE_LIMIT", "50"))
DEFAULT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))

_KEY_PREFIX = "ratelimit:"


async def acquire(
    domain: str,
    max_requests: int | None = None,
    window_seconds: int = DEFAULT_WINDOW,
) -> bool:
    """Return True if a request slot is available for *domain*.

    Uses a Redis sorted-set sliding window: members are timestamps, and we
    count how many fall within the last *window_seconds*.
    """
    limit = max_requests or DEFAULT_RATE_LIMIT
    key = f"{_KEY_PREFIX}{domain}"
    now = time.time()
    window_start = now - window_seconds

    r = get_redis()
    pipe = r.pipeline()
    # Remove expired entries
    pipe.zremrangebyscore(key, 0, window_start)
    # Count current entries
    pipe.zcard(key)
    results = await pipe.execute()
    current_count = results[1]

    if current_count >= limit:
        return False

    # Add this request
    await r.zadd(key, {str(now): now})
    await r.expire(key, window_seconds + 1)
    return True


async def wait_and_acquire(
    domain: str,
    max_requests: int | None = None,
    window_seconds: int = DEFAULT_WINDOW,
    timeout: float = 30.0,
) -> bool:
    """Wait until a rate-limit slot opens, then acquire it.

    Returns False only if *timeout* is exceeded.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if await acquire(domain, max_requests, window_seconds):
            return True
        # Back off briefly before retrying
        await asyncio.sleep(0.25)
    return False


async def get_current_rate(
    domain: str,
    window_seconds: int = DEFAULT_WINDOW,
) -> int:
    """Return the number of requests recorded in the current window."""
    key = f"{_KEY_PREFIX}{domain}"
    now = time.time()
    window_start = now - window_seconds
    r = get_redis()
    await r.zremrangebyscore(key, 0, window_start)
    return await r.zcard(key)


async def reset(domain: str) -> None:
    """Clear rate-limit state for a domain."""
    r = get_redis()
    await r.delete(f"{_KEY_PREFIX}{domain}")


# ---------------------------------------------------------------------------
# Stackable rule-based rate limiter
# ---------------------------------------------------------------------------

_UNIT_SHORTCUTS = {"s": 1, "min": 60, "hr": 3600, "day": 86400}
_SIZE_MULTIPLIERS = {"bytes": 1, "KB": 1024, "MB": 1024 * 1024}
_RULE_RE = _re.compile(
    r"^(req|bytes|KB|MB)/(s|\d+s|min|hr|day)$"
)


@dataclass
class RateRule:
    """A single rate limiting rule."""
    amount: int
    window_seconds: int
    rule_type: str  # "request" | "bandwidth"


def parse_rate_rule(rule_dict: dict) -> RateRule:
    """Parse a rate rule from a dict like {"amount": 50, "unit": "req/s"}.

    Supported units:
    - Request: req/s, req/Ns, req/min, req/hr, req/day
    - Bandwidth: bytes/s, KB/s, MB/s, KB/Ns, MB/min, MB/hr, etc.
    """
    amount = rule_dict["amount"]
    unit = rule_dict["unit"]

    match = _RULE_RE.match(unit)
    if not match:
        raise ValueError(f"Invalid rate limit unit: {unit}")

    size_or_req = match.group(1)
    time_part = match.group(2)

    # Determine rule type and apply size multiplier
    if size_or_req == "req":
        rule_type = "request"
    else:
        rule_type = "bandwidth"
        amount = amount * _SIZE_MULTIPLIERS[size_or_req]

    # Parse time window
    if time_part in _UNIT_SHORTCUTS:
        window_seconds = _UNIT_SHORTCUTS[time_part]
    elif time_part.endswith("s") and time_part[:-1].isdigit():
        window_seconds = int(time_part[:-1])
    else:
        raise ValueError(f"Invalid time window: {time_part}")

    return RateRule(amount=amount, window_seconds=window_seconds, rule_type=rule_type)


class RateLimiter:
    """Stackable rate limiter with multiple concurrent rules.

    Each rule is enforced independently using a Redis sorted set.
    The most restrictive rule at any moment determines whether to block.
    """

    def __init__(self, redis_client, campaign_id: int, rules: list[RateRule]) -> None:
        self._redis = redis_client
        self._campaign_id = campaign_id
        self._rules = rules

    async def acquire(self, response_bytes: int = 0) -> None:
        """Check all rules and wait if any are exceeded.

        For bandwidth rules, response_bytes is the size of the response to track.
        """
        for i, rule in enumerate(self._rules):
            key = f"{_KEY_PREFIX}campaign:{self._campaign_id}:rule:{i}"
            now = time.time()
            window_start = now - rule.window_seconds

            while True:
                pipe = self._redis.pipeline()
                pipe.zremrangebyscore(key, 0, window_start)
                pipe.zcard(key)
                results = await pipe.execute()
                current = results[1]

                if current < rule.amount:
                    break

                # Exceeded — wait and retry
                await asyncio.sleep(0.1)
                now = time.time()
                window_start = now - rule.window_seconds

            # Record this request/bytes
            value = response_bytes if rule.rule_type == "bandwidth" else 1
            await self._redis.zadd(key, {f"{now}:{value}": now})
            await self._redis.expire(key, rule.window_seconds + 1)
