# orchestrator/event_engine.py
import asyncio
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh.database import get_session, Target, JobState
from lib_webbh.messaging import push_priority_task
from lib_webbh import setup_logger

from .dependency_map import resolve_effective_dependencies, CREDENTIAL_REQUIRED
from .resource_guard import ResourceGuard

logger = setup_logger("event_engine")


class EventEngine:
    """Evaluates worker dependencies and dispatches next workers."""

    def __init__(self, resource_guard: ResourceGuard):
        self.resource_guard = resource_guard
        self._poll_interval = 5

    async def run(self):
        while True:
            try:
                await self._poll_cycle()
            except Exception as e:
                logger.error("Event engine error", error=str(e))
            await asyncio.sleep(self._poll_interval)

    async def _poll_cycle(self):
        tier = await self.resource_guard.get_current_tier()
        if tier == "critical":
            return

        async with get_session() as session:
            targets = await session.execute(
                select(Target).where(Target.target_type.in_(["seed", "child"]))
            )
            targets = targets.scalars().all()

        for target in targets:
            await self._evaluate_target(target, tier)

    async def _evaluate_target(self, target, resource_tier):
        has_creds = self._check_credentials(target.id)
        dep_map = resolve_effective_dependencies(has_credentials=has_creds)
        worker_states = await self._get_worker_states(target.id)

        for worker_name, dependencies in dep_map.items():
            if worker_states.get(worker_name) in ("running", "complete", "queued"):
                continue

            all_deps_met = all(
                worker_states.get(dep) == "complete"
                for dep in dependencies
            )

            if not all_deps_met:
                continue

            batch_config = self.resource_guard.get_batch_config(resource_tier)
            priority = target.priority or 50

            if priority >= 90:
                queue_tier = "critical"
            elif priority >= 70:
                queue_tier = "high"
            elif priority >= 50:
                queue_tier = "normal"
            else:
                queue_tier = "low"

            if queue_tier not in batch_config["queues"]:
                continue

            await self._dispatch_worker(target, worker_name, queue_tier)

    async def _dispatch_worker(self, target, worker_name, queue_tier):
        queue_name = f"{worker_name}_queue"
        await push_priority_task(
            queue_name,
            {"target_id": target.id, "worker": worker_name},
            priority_score=target.priority or 50,
        )

        async with get_session() as session:
            job = JobState(
                target_id=target.id,
                container_name=worker_name,
                status="queued",
                queued_at=datetime.now(timezone.utc),
            )
            session.add(job)
            await session.commit()

        logger.info("Worker dispatched", worker=worker_name, target_id=target.id)

    async def _get_worker_states(self, target_id):
        async with get_session() as session:
            jobs = await session.execute(
                select(JobState)
                .where(JobState.target_id == target_id)
                .order_by(JobState.created_at.desc())
            )
            states = {}
            for job in jobs.scalars().all():
                if job.container_name not in states:
                    states[job.container_name] = job.status
            return states

    def _check_credentials(self, target_id):
        from pathlib import Path
        return Path(f"shared/config/{target_id}/credentials.json").exists()