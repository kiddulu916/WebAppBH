"""Redis-backed sliding window rate limiter."""
from __future__ import annotations

import time
from fastapi import Request, HTTPException
from lib_webbh.messaging import get_redis


# Defaults: 60 requests per minute for mutating, 200 for reads
RATE_LIMITS = {
    "POST": {"window": 60, "max_requests": 60},
    "PATCH": {"window": 60, "max_requests": 60},
    "PUT": {"window": 60, "max_requests": 60},
    "DELETE": {"window": 60, "max_requests": 60},
    "GET": {"window": 60, "max_requests": 200},
}


async def rate_limit_check(request: Request) -> None:
    """Check rate limit. Raises 429 if exceeded."""
    method = request.method
    config = RATE_LIMITS.get(method)
    if not config:
        return

    try:
        redis = get_redis()
    except Exception:
        return  # If Redis is unavailable, skip rate limiting

    client_ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:{client_ip}:{method}"
    now = time.time()
    window = config["window"]
    max_req = config["max_requests"]

    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, now - window)
    pipe.zadd(key, {str(now): now})
    pipe.zcard(key)
    pipe.expire(key, window)
    results = await pipe.execute()
    count = results[2]

    if count > max_req:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {max_req} requests per {window}s",
        )
