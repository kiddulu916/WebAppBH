"""Reporting worker entry point."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import Any

from sqlalchemy import select

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, Target
from lib_webbh.messaging import listen_queue, push_task

from workers.reporting_worker.pipeline import Pipeline

logger = setup_logger("reporting_worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "reporting-worker-unknown")


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    while True:
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                row = (await session.execute(stmt)).scalar_one_or_none()
                if row:
                    row.last_seen = datetime.utcnow()
                    await session.commit()
        except Exception:
            pass
        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def handle_message(msg_id: str, data: dict[str, Any]) -> None:
    target_id = data["target_id"]
    formats = data.get("formats", ["hackerone_md"])
    platform = data.get("platform", "hackerone")
    container_name = get_container_name()
    log = logger.bind(target_id=target_id, container=container_name)
    log.info("Received report task", extra={"formats": formats, "platform": platform})

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            log.error("Target not found")
            return

        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        job = (await session.execute(stmt)).scalar_one_or_none()
        if job is None:
            job = JobState(
                target_id=target_id, container_name=container_name,
                status="RUNNING", current_phase="init",
                last_seen=datetime.utcnow(),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.current_phase = "init"
            job.last_seen = datetime.utcnow()
        await session.commit()

    heartbeat = asyncio.create_task(_heartbeat_loop(target_id, container_name))

    try:
        pipeline = Pipeline()
        await pipeline.run(
            target_id=target_id,
            formats=formats,
            platform=platform,
            container_name=container_name,
        )
    except Exception as exc:
        log.error("Pipeline failed", extra={"error": str(exc)})
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            job = (await session.execute(stmt)).scalar_one_or_none()
            if job:
                job.status = "FAILED"
                await session.commit()
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass


async def main() -> None:
    logger.info("Reporting worker starting")
    container_name = get_container_name()
    logger.info("Listening for tasks", extra={"consumer": container_name})
    await listen_queue(
        queue="report_queue", group="reporting_group",
        consumer=container_name, callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
