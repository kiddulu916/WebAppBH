"""API testing worker entry point.

Listens on ``api_queue`` and runs the 4-stage
API testing pipeline for each incoming target.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_queue,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.api_worker.pipeline import Pipeline

logger = setup_logger("api-worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "api-worker-unknown")


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single api_queue message."""
    target_id = data.get("target_id")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info("Received api testing task", extra={"msg_id": msg_id})

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
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.now(timezone.utc)
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
                job.last_seen = datetime.now(timezone.utc)
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
                    job.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass


async def main() -> None:
    """Entry point: listen on api_queue forever."""
    container_name = get_container_name()
    logger.info("API testing worker starting", extra={"container": container_name})

    await listen_queue(
        queue="api_queue",
        group="api_group",
        consumer=container_name,
        callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
