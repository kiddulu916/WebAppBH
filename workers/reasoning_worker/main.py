"""Reasoning worker — LLM-powered vulnerability analysis."""
from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone

from sqlalchemy import delete, update

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState
from lib_webbh.messaging import listen_priority_queues, get_redis

from workers.reasoning_worker.pipeline import Pipeline

logger = setup_logger("reasoning_worker")

WORKER_TYPE = "reasoning_worker"


async def main() -> None:
    logger.info("Reasoning worker starting")
    consumer_group = "reasoning_worker_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"
    logger.info("Listening for tasks", extra={"consumer": consumer_name})

    async for message in listen_priority_queues(
        "reasoning_worker_queue", consumer_group, consumer_name
    ):
        target_id = message["payload"]["target_id"]
        logger.info("Job received", extra={"target_id": target_id})

        try:
            async with get_session() as session:
                await session.execute(
                    delete(JobState).where(
                        JobState.target_id == target_id,
                        JobState.container_name == WORKER_TYPE,
                    )
                )
                session.add(JobState(
                    target_id=target_id,
                    container_name=WORKER_TYPE,
                    status="RUNNING",
                    started_at=datetime.now(timezone.utc),
                ))
                await session.commit()

            pipeline = Pipeline(target_id=target_id, container_name=WORKER_TYPE)
            async with get_session() as session:
                insight_count = await pipeline.run(session)
            logger.info("Reasoning complete", extra={"target_id": target_id, "insights": insight_count})

            async with get_session() as session:
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="COMPLETED", completed_at=datetime.now(timezone.utc))
                )
                await session.commit()

        except Exception as exc:
            logger.error("Reasoning failed", extra={"target_id": target_id, "error": str(exc)})
            try:
                async with get_session() as session:
                    await session.execute(
                        update(JobState)
                        .where(JobState.target_id == target_id)
                        .where(JobState.container_name == WORKER_TYPE)
                        .values(status="FAILED", error=str(exc)[:500])
                    )
                    await session.commit()
            except Exception:
                pass

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
