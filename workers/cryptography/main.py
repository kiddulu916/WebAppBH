# workers/cryptography/main.py
import asyncio
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, update

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, Target
from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.scope import ScopeManager

from .pipeline import Pipeline

logger = setup_logger("cryptography")

WORKER_TYPE = "cryptography"


def _load_playbook(target_id: int) -> dict | None:
    path = Path(f"shared/config/{target_id}/playbook.json")
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


async def main():
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

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
            else:
                scope_manager = ScopeManager(
                    target.target_profile or {"in_scope_domains": [f"*.{target.base_domain}"]}
                )
                playbook = _load_playbook(target_id)
                pipeline = Pipeline(target_id=target_id, container_name=WORKER_TYPE)
                await pipeline.run(target, scope_manager, playbook=playbook)

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
            async with get_session() as session:
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="FAILED", error=str(e))
                )
                await session.commit()

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
