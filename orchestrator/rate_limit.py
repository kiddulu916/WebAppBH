"""Redis-backed sliding window rate limiter."""
from __future__ import annotations

import os
import time

from fastapi import HTTPException, Request

from lib_webbh import setup_logger
from lib_webbh.messaging import get_redis

logger = setup_logger("rate_limit")


def _parse_positive_int(name: str, default: int) -> int:
    """Parse an env var as a positive integer, falling back to default on bad input."""
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            f"Invalid value for {name} ({raw!r}); falling back to {default}"
        )
        return default
    if value <= 0:
        logger.warning(
            f"Non-positive value for {name} ({value}); falling back to {default}"
        )
        return default
    return value


_mutate_max = _parse_positive_int("RATE_LIMIT_MUTATE", 60)
_read_max = _parse_positive_int("RATE_LIMIT_READ", 200)

# When True, requests are denied (fail-closed) if the rate limiter cannot
# reach Redis. Default is True so a Redis outage cannot silently disable
# rate limiting. Set RATE_LIMIT_FAIL_OPEN=1 to allow requests through.
_FAIL_OPEN = os.getenv("RATE_LIMIT_FAIL_OPEN", "").lower() in ("1", "true", "yes")

# Defaults: 60 requests per minute for mutating, 200 for reads
RATE_LIMITS = {
    "POST": {"window": 60, "max_requests": _mutate_max},
    "PATCH": {"window": 60, "max_requests": _mutate_max},
    "PUT": {"window": 60, "max_requests": _mutate_max},
    "DELETE": {"window": 60, "max_requests": _mutate_max},
    "GET": {"window": 60, "max_requests": _read_max},
}


async def rate_limit_check(request: Request) -> None:
    """Check rate limit. Raises 429 if exceeded, 503 if Redis is unreachable."""
    method = request.method
    config = RATE_LIMITS.get(method)
    if not config:
        return

    try:
        redis = get_redis()
    except Exception as exc:
        logger.error(f"Rate limiter could not obtain Redis client: {exc}")
        if _FAIL_OPEN:
            return
        raise HTTPException(status_code=503, detail="Rate limiter unavailable") from exc

    client_ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:{client_ip}:{method}"
    now = time.time()
    window = config["window"]
    max_req = config["max_requests"]

    try:
        pipe = redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window)
        results = await pipe.execute()
    except Exception as exc:
        logger.error(f"Rate limiter Redis pipeline failed: {exc}")
        if _FAIL_OPEN:
            return
        raise HTTPException(status_code=503, detail="Rate limiter unavailable") from exc

    count = results[2]

    if count > max_req:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {max_req} requests per {window}s",
        )
