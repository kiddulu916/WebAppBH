"""Recon-Core worker entry point.

Listens on ``recon_queue`` and runs the 5-stage reconnaissance
pipeline for each incoming target.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_queue,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.recon_core.pipeline import Pipeline

logger = setup_logger("recon-core")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "recon-core-unknown")


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single recon_queue message."""
    target_id = data.get("target_id")
    action = data.get("action", "full_recon")

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

    if target is None:
        log.error(f"Target {target_id} not found in database")
        return

    container_name = get_container_name()
    profile = target.target_profile or {}
    headers = profile.get("custom_headers", {})
    scope_manager = ScopeManager(profile)

    config_dir = Path("shared/config") / str(target_id)
    playbook_path = config_dir / "playbook.json"
    playbook = json.loads(playbook_path.read_text()) if playbook_path.exists() else None

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
        await pipeline.run(target, scope_manager, headers=headers, playbook=playbook)
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
    """Entry point: listen on recon_queue forever."""
    container_name = get_container_name()
    logger.info("Recon-Core starting", extra={"container": container_name})

    await listen_queue(
        queue="recon_queue",
        group="recon_group",
        consumer=container_name,
        callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
