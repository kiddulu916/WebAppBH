# workers/error_handling/main.py
import asyncio
import os
import socket

from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.database import get_session, JobState
from lib_webbh import setup_logger

from .pipeline import STAGES
from .concurrency import get_semaphores, TOOL_WEIGHTS

logger = setup_logger("error_handling")

WORKER_TYPE = "error_handling"


async def run_pipeline(target_id: int):
    """Run all stages sequentially, tools within each stage concurrently."""
    heavy_sem, light_sem = get_semaphores()

    for stage_idx, stage in enumerate(STAGES):
        logger.info("Stage started", stage=stage.name, section_id=stage.section_id)

        # Update job state
        async with get_session() as session:
            from sqlalchemy import select, update
            await session.execute(
                update(JobState)
                .where(JobState.target_id == target_id)
                .where(JobState.container_name == WORKER_TYPE)
                .values(
                    current_phase=stage.name,
                    current_section_id=stage.section_id,
                    last_tool_executed=None,
                )
            )
            await session.commit()

        # Run tools concurrently within the stage
        async def run_tool(tool_cls):
            weight = TOOL_WEIGHTS.get(tool_cls.__name__, "LIGHT")
            sem = heavy_sem if weight == "HEAVY" else light_sem
            async with sem:
                tool = tool_cls()
                await tool.execute(target_id)

        await asyncio.gather(*(run_tool(t) for t in stage.tools))

        logger.info("Stage complete", stage=stage.name)


async def main():
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

    async for message in listen_priority_queues(
        f"{WORKER_TYPE}_queue", consumer_group, consumer_name
    ):
        target_id = message["payload"]["target_id"]
        logger.info("Job received", target_id=target_id)

        try:
            # Create/update job state
            async with get_session() as session:
                from datetime import datetime, timezone
                job = JobState(
                    target_id=target_id,
                    container_name=WORKER_TYPE,
                    status="RUNNING",
                    started_at=datetime.now(timezone.utc),
                )
                session.add(job)
                await session.commit()

            await run_pipeline(target_id)

            # Mark complete
            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="COMPLETED", completed_at=datetime.now(timezone.utc))
                )
                await session.commit()

        except Exception as e:
            logger.error("Job failed", target_id=target_id, error=str(e))
            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="FAILED", error=str(e))
                )
                await session.commit()

        # ACK the message
        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())