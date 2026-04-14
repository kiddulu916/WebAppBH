"""Centralized sliding-window rate limiter backed by Redis.

All workers should call ``acquire()`` or ``wait_and_acquire()`` before making
HTTP requests to a target domain, preventing accidental DoS and WAF bans.
"""
from __future__ import annotations

import asyncio
import os
import time

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
