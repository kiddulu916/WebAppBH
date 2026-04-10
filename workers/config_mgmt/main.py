"""Config management worker entry point.

Listens on ``config_mgmt_queue`` (priority-tiered) and runs the 11-stage
config management pipeline for each incoming target.
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

from workers.config_mgmt.pipeline import Pipeline

logger = setup_logger("config-mgmt")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "config-mgmt-unknown")


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single config_mgmt_queue message."""
    target_id = data.get("target_id")
    action = data.get("action", "full_config_mgmt")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info(f"Received {action}", extra={"msg_id": msg_id})

    # Load target
    async with get_session() as session:
        stmt = select(Target).where(Target.id == target_id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

    if not target:
        log.error("Target not found", extra={"target_id": target_id})
        return

    # Create scope manager
    scope_manager = ScopeManager(target.scope_config or {})

    # Get or create job state
    container_name = get_container_name()
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if not job:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                status="RUNNING",
                current_phase="",
                job_type="config_mgmt",
            )
            session.add(job)
            await session.commit()
            log.info("Created new job state")
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.utcnow()
            await session.commit()
            log.info("Resumed existing job state")

    # Run pipeline with heartbeat
    try:
        pipeline = Pipeline(target_id, container_name)
        await asyncio.wait_for(
            _run_pipeline_with_heartbeat(pipeline, target, scope_manager),
            timeout=None,  # Let it run until completion
        )
        log.info("Pipeline completed successfully")
    except Exception as e:
        log.error("Pipeline failed", extra={"error": str(e)})
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


async def _run_pipeline_with_heartbeat(
    pipeline: Pipeline, target, scope_manager: ScopeManager
) -> None:
    """Run the pipeline while maintaining a heartbeat."""
    heartbeat_task = asyncio.create_task(_heartbeat_loop(pipeline.target_id, pipeline.container_name))
    try:
        await pipeline.run(target, scope_manager)
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
        except Exception as e:
            logger.warning("Heartbeat update failed", extra={"error": str(e)})


async def main() -> None:
    """Start the config management worker."""
    consumer_group = "config_mgmt_group"
    consumer_name = get_container_name()
    logger.info("Starting config management worker")

    async for message in listen_priority_queues(
        "config_mgmt_queue", consumer_group, consumer_name
    ):
        try:
            await handle_message(message["msg_id"], message["payload"])
        except Exception as e:
            logger.error("Message handling failed", extra={"error": str(e)})

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())