from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable

import redis.asyncio as aioredis

_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        host = os.environ.get("REDIS_HOST", "localhost")
        port = int(os.environ.get("REDIS_PORT", "6379"))
        max_connections = int(os.environ.get("REDIS_MAX_CONNECTIONS", "50"))
        _redis = aioredis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            max_connections=max_connections,
        )
    return _redis


async def push_task(queue: str, data: dict[str, Any], correlation_id: str | None = None) -> str:
    """Push a task message to a Redis Stream."""
    r = get_redis()
    if correlation_id:
        data = {**data, "_correlation_id": correlation_id}
    payload = json.dumps(data, default=str)
    timestamp = datetime.now(timezone.utc).isoformat()
    msg_id: str = await r.xadd(queue, {"payload": payload, "timestamp": timestamp})
    return msg_id


async def listen_queue(
    queue: str,
    group: str,
    consumer: str,
    callback: Callable[[str, dict[str, Any]], Awaitable[None]],
) -> None:
    r = get_redis()
    try:
        await r.xgroup_create(queue, group, id="0", mkstream=True)
    except aioredis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise

    while True:
        messages = await r.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={queue: ">"},
            count=10,
            block=5000,
        )
        if not messages:
            continue
        for stream_name, stream_messages in messages:
            for msg_id, fields in stream_messages:
                data = json.loads(fields["payload"])
                await callback(msg_id, data)
                await r.xack(queue, group, msg_id)


async def push_priority_task(
    queue_prefix: str,
    data: dict[str, Any],
    priority_score: int,
) -> str:
    """Push a task to the appropriate priority-tiered stream.

    Priority tiers:
        >= 90 → :critical
        >= 70 → :high
        >= 50 → :normal
        <  50 → :low
    """
    if priority_score >= 90:
        tier = "critical"
    elif priority_score >= 70:
        tier = "high"
    elif priority_score >= 50:
        tier = "normal"
    else:
        tier = "low"

    return await push_task(f"{queue_prefix}:{tier}", data)


async def get_pending(queue: str, group: str) -> dict[str, Any]:
    r = get_redis()
    info = await r.xpending(queue, group)
    pending_count = 0
    if isinstance(info, dict):
        pending_count = info.get("pending", 0)
    elif isinstance(info, (list, tuple)) and len(info) > 0:
        pending_count = info[0] if isinstance(info[0], int) else 0
    return {"pending": pending_count, "raw": info}


async def listen_priority_queues(
    queue_prefix: str,
    group: str,
    consumer: str,
) -> AsyncIterator[dict[str, Any]]:
    """Read from priority-tiered queues with weighted consumption.

    Yields dicts with keys: stream, msg_id, payload.
    Higher-priority tiers are consumed first each cycle.
    """
    r = get_redis()
    tier_config = [
        ("critical", 5),
        ("high", 3),
        ("normal", 2),
        ("low", 1),
    ]

    # Ensure consumer groups exist
    for tier_name, _ in tier_config:
        stream_name = f"{queue_prefix}:{tier_name}"
        try:
            await r.xgroup_create(stream_name, group, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    while True:
        yielded_any = False

        for tier_name, batch_size in tier_config:
            stream_name = f"{queue_prefix}:{tier_name}"
            messages = await r.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={stream_name: ">"},
                count=batch_size,
                block=100,
            )
            if not messages:
                continue
            for s_name, stream_messages in messages:
                for msg_id, fields in stream_messages:
                    payload = json.loads(fields["payload"])
                    yielded_any = True
                    yield {
                        "stream": s_name,
                        "msg_id": msg_id,
                        "payload": payload,
                    }

        if not yielded_any:
            await asyncio.sleep(1)
