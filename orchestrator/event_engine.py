# orchestrator/event_engine.py
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select, delete

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
                logger.error("Event engine error", extra={"error": str(e)})
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

    def _get_disabled_workers(self, target_id: int) -> set[str]:
        """Return the set of workers disabled in this target's playbook."""
        playbook_path = Path(f"shared/config/{target_id}/playbook.json")
        if not playbook_path.exists():
            return set()
        try:
            data = json.loads(playbook_path.read_text())
            return {
                w["name"]
                for w in data.get("workers", [])
                if not w.get("enabled", True)
            }
        except Exception:
            return set()

    async def _evaluate_target(self, target, resource_tier):
        has_creds = self._check_credentials(target.id)
        dep_map = resolve_effective_dependencies(has_credentials=has_creds)
        worker_states = await self._get_worker_states(target.id)
        disabled = self._get_disabled_workers(target.id)

        for worker_name, dependencies in dep_map.items():
            if worker_name in disabled:
                continue

            if worker_states.get(worker_name) in ("RUNNING", "COMPLETED", "QUEUED", "KILLED", "STOPPED"):
                continue

            # Treat disabled dependency workers as already completed
            all_deps_met = all(
                dep in disabled or worker_states.get(dep) == "COMPLETED"
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
            await session.execute(
                delete(JobState).where(
                    JobState.target_id == target.id,
                    JobState.container_name == worker_name,
                )
            )
            session.add(JobState(
                target_id=target.id,
                container_name=worker_name,
                status="QUEUED",
                queued_at=datetime.now(timezone.utc),
            ))
            await session.commit()

        logger.info("Worker dispatched", extra={"worker": worker_name, "target_id": target.id})

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
        return Path(f"shared/config/{target_id}/credentials.json").exists()