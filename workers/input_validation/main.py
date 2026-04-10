"""Input Validation worker entry point.

Listens on ``input_validation_queue`` (priority-tiered) and runs the 15-stage
input validation pipeline for each incoming target.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_priority_queues,
    setup_logger,
)
from lib_webbh.messaging import get_redis
from lib_webbh.scope import ScopeManager

from workers.input_validation.pipeline import Pipeline

logger = setup_logger("input-validation")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "input-validation-unknown")


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single input_validation_queue message."""
    target_id = data.get("target_id")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info("Received input validation request", extra={"msg_id": msg_id})

    # Load target
    async with get_session() as session:
        stmt = select(Target).where(Target.id == target_id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

    if target is None:
        log.error(f"Target {target_id} not found in database")
        return

    container_name = get_container_name()
    profile = target.target_profile or {}
    headers = profile.get("custom_headers", {})
    scope_manager = ScopeManager(profile)

    # Ensure job_state row
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if job is None:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                current_phase="init",
                status="RUNNING",
                last_seen=datetime.utcnow(),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.utcnow()
        await session.commit()

    # Run pipeline with heartbeat
    pipeline = Pipeline(target_id=target_id, container_name=container_name)
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(target_id, container_name)
    )

    try:
        await pipeline.run(target, scope_manager, headers=headers)
    except Exception:
        log.exception("Pipeline failed")
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "FAILED"
                job.last_seen = datetime.utcnow()
                await session.commit()
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    """Update job_state.last_seen every HEARTBEAT_INTERVAL seconds."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_seen = datetime.utcnow()
                    await session.commit()
        except Exception:
            pass


async def main() -> None:
    """Entry point: listen on input_validation_queue forever."""
    consumer_group = "input_validation_group"
    consumer_name = get_container_name()
    logger.info("Input Validation starting", extra={"container": consumer_name})

    async for message in listen_priority_queues(
        "input_validation_queue", consumer_group, consumer_name
    ):
        try:
            await handle_message(message["msg_id"], message["payload"])
        except Exception as e:
            logger.error("Message handling failed", extra={"error": str(e)})

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())