"""
One-time script to drain and delete old Redis streams.

Run AFTER verifying no active campaigns use the old streams
and AFTER all new workers (M1-M10) are operational.

See: docs/plans/implementation/2026-04-01-legacy-worker-retirement-status.md

Usage:
    python scripts/migrate_redis_streams.py

Environment:
    REDIS_HOST  — Redis host (default: localhost)
    REDIS_PORT  — Redis port (default: 6379)
"""
import asyncio
import os

import redis.asyncio as aioredis

OLD_STREAMS = [
    "recon_queue",
    "fuzzing_queue",
    "cloud_queue",
    "api_queue",
    "network_queue",
    "webapp_queue",
    "vuln_scanner_queue",
]


async def main():
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", "6379"))

    r = aioredis.Redis(host=redis_host, port=redis_port, decode_responses=True)

    print(f"Connecting to Redis at {redis_host}:{redis_port}...")
    await r.ping()
    print("Connected.\n")

    deleted = 0
    skipped = 0
    warned = 0

    for stream in OLD_STREAMS:
        exists = await r.exists(stream)
        if not exists:
            print(f"  {stream}: does not exist, skipping")
            skipped += 1
            continue

        pending = await r.xlen(stream)
        if pending > 0:
            print(f"  WARNING: {stream} has {pending} pending messages!")
            print(f"  These messages will be lost. Skipping. To force: redis-cli DEL {stream}")
            warned += 1
            continue

        await r.delete(stream)
        print(f"  {stream}: deleted")
        deleted += 1

    await r.aclose()
    print(f"\nRedis stream cleanup complete: {deleted} deleted, {skipped} skipped, {warned} warned.")


if __name__ == "__main__":
    asyncio.run(main())
