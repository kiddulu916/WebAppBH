"""Input Validation worker entry point."""

from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone

from sqlalchemy import delete, update

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

logger = setup_logger("input_validation")

WORKER_TYPE = "input_validation"


async def main() -> None:
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"
    logger.info("Input validation worker starting")

    async for message in listen_priority_queues(
        f"{WORKER_TYPE}_queue", consumer_group, consumer_name
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

            async with get_session() as session:
                target = await session.get(Target, target_id)
            if target is None:
                logger.error("Target not found", extra={"target_id": target_id})
                r = get_redis()
                await r.xack(message["stream"], consumer_group, message["msg_id"])
                continue

            profile = target.target_profile or {
                "in_scope_domains": [f"*.{target.base_domain}", target.base_domain]
            }
            scope_manager = ScopeManager(profile)
            headers = profile.get("custom_headers", {})

            pipeline = Pipeline(target_id=target_id, container_name=WORKER_TYPE)
            await pipeline.run(target, scope_manager, headers=headers)

            async with get_session() as session:
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="COMPLETED", completed_at=datetime.now(timezone.utc))
                )
                await session.commit()

        except Exception as e:
            logger.error("Job failed", extra={"target_id": target_id, "error": str(e)})
            try:
                async with get_session() as session:
                    await session.execute(
                        update(JobState)
                        .where(JobState.target_id == target_id)
                        .where(JobState.container_name == WORKER_TYPE)
                        .values(status="FAILED", error=str(e)[:500])
                    )
                    await session.commit()
            except Exception:
                pass

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
