"""Sandbox worker: payload mutation service.

Listens on ``sandbox_queue`` for mutation requests from other workers
(client_side, input_validation). Returns ranked mutation variants to
the caller's reply queue.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, MutationOutcome
from lib_webbh.messaging import listen_queue, push_task
from sqlalchemy import select

from workers.sandbox_worker.chaining import chain_mutate
from workers.sandbox_worker.context import InjectionContext
from workers.sandbox_worker.mutator import mutate
from workers.sandbox_worker.payload_corpus import CORPUS
from workers.sandbox_worker.waf_fingerprint import fingerprint_waf

logger = setup_logger("sandbox_worker")

QUEUE_NAME = os.environ.get("SANDBOX_QUEUE", "sandbox_queue")
CONSUMER_GROUP = "sandbox_workers"
CONSUMER_NAME = f"sandbox_{os.getpid()}"
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "15"))


async def handle_message(data: dict) -> dict:
    """Process a mutation request and return ranked variants."""
    msg_type = data.get("type", "mutate")
    vuln_type = data.get("vuln_type", "xss")
    base_payload = data.get("base_payload")
    context_str = data.get("context")
    waf_profile = data.get("waf_profile")
    depth = int(data.get("depth", 2))

    context = None
    if context_str:
        try:
            context = InjectionContext(context_str)
        except ValueError:
            pass

    if msg_type == "fingerprint":
        waf = fingerprint_waf(
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            status_code=int(data.get("status_code", 200)),
            cookies=data.get("cookies"),
        )
        return {"waf_profile": waf}

    # Get seed payloads if no base payload provided
    payloads: list[str] = []
    if base_payload:
        payloads = [base_payload]
    else:
        for key, seeds in CORPUS.items():
            if key[0] == vuln_type:
                payloads.extend(seeds)
                break

    if not payloads:
        return {"variants": [], "count": 0}

    all_variants: list[str] = []
    for p in payloads:
        if depth > 1:
            variants = chain_mutate(p, vuln_type, depth=depth, context=context)
        else:
            variants = mutate(p, vuln_type, context=context)
        all_variants.extend(variants)

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for v in all_variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)

    result = {
        "variants": unique[:int(os.environ.get("MAX_VARIANTS_PER_REQUEST", "50"))],
        "count": len(unique),
        "vuln_type": vuln_type,
        "waf_profile": waf_profile,
    }

    # Push reply if reply_queue specified
    reply_queue = data.get("reply_queue")
    if reply_queue:
        result["correlation_id"] = data.get("reply_correlation_id")
        await push_task(reply_queue, result)

    return result


async def heartbeat(container_name: str) -> None:
    """Periodic heartbeat to update job_state."""
    while True:
        try:
            async with get_session() as session:
                row = (await session.execute(
                    select(JobState).where(
                        JobState.container_name == container_name
                    )
                )).scalar_one_or_none()
                if row:
                    row.last_seen = datetime.now(timezone.utc)
                    row.status = "RUNNING"
                    await session.commit()
        except Exception as exc:
            logger.warning("Heartbeat failed", extra={"error": str(exc)})
        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def main() -> None:
    container_name = "sandbox-worker"
    logger.info("Sandbox worker starting", extra={"queue": QUEUE_NAME})

    asyncio.create_task(heartbeat(container_name))

    async for msg_id, data in listen_queue(
        QUEUE_NAME, CONSUMER_GROUP, CONSUMER_NAME
    ):
        try:
            result = await handle_message(data)
            logger.info("Mutation request processed", extra={
                "vuln_type": data.get("vuln_type"),
                "variants": result.get("count", 0),
            })
        except Exception as exc:
            logger.error("Message handling failed", extra={"error": str(exc)})


if __name__ == "__main__":
    asyncio.run(main())
