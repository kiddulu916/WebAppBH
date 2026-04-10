"""Reasoning worker — LLM-powered vulnerability analysis."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import Any

from sqlalchemy import select

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState
from lib_webbh.messaging import listen_priority_queues, get_redis

from workers.reasoning_worker.analyzer import analyze_findings

logger = setup_logger("reasoning_worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "reasoning-worker-unknown")


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
    container_name = get_container_name()
    log = logger.bind(target_id=target_id, container=container_name)
    log.info("Received reasoning task")

    # Create or update job state
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        job = (await session.execute(stmt)).scalar_one_or_none()
        if job is None:
            job = JobState(
                target_id=target_id, container_name=container_name,
                status="RUNNING", current_phase="reasoning",
                last_seen=datetime.utcnow(),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.current_phase = "reasoning"
            job.last_seen = datetime.utcnow()
        await session.commit()

    heartbeat = asyncio.create_task(_heartbeat_loop(target_id, container_name))

    try:
        async with get_session() as session:
            insight_count = await analyze_findings(target_id, session)
            log.info("Reasoning complete", extra={"insights": insight_count})

        # Mark completed
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            job = (await session.execute(stmt)).scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.last_seen = datetime.utcnow()
                await session.commit()

    except Exception as exc:
        log.error("Reasoning failed", extra={"error": str(exc)})
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
    logger.info("Reasoning worker starting")
    consumer_group = "reasoning_worker_group"
    consumer_name = get_container_name()
    logger.info("Listening for tasks", extra={"consumer": consumer_name})

    async for message in listen_priority_queues(
        "reasoning_queue", consumer_group, consumer_name
    ):
        try:
            await handle_message(message["msg_id"], message["payload"])
        except Exception as e:
            logger.error("Message handling failed", extra={"error": str(e)})

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
