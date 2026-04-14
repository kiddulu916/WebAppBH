"""Pipeline checkpoint mixin — shared resume/checkpoint logic for all worker pipelines."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from lib_webbh import JobState, get_session


class CheckpointMixin:
    """Mixin providing crash-safe pipeline checkpoint and resume.

    Requires ``self.target_id`` and ``self.container_name`` on the host class.

    The key insight: ``current_phase`` tracks what stage is *currently executing*
    (set before the stage runs), while ``last_completed_stage`` tracks the last
    stage that *finished successfully* (set after the stage completes). On crash
    recovery we resume from ``last_completed_stage + 1``, regardless of job status.
    """

    target_id: int
    container_name: str

    async def _get_resume_stage(self) -> str | None:
        """Return the last successfully completed stage name, or None.

        Queries any existing job for this target+container — not just COMPLETED
        jobs — so crash recovery (RUNNING/FAILED status) works correctly.
        """
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            return job.last_completed_stage if job else None

    async def _update_phase(self, phase: str) -> None:
        """Mark a stage as *in-progress* (called before running the stage)."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.current_phase = phase
                job.status = "RUNNING"
                job.last_seen = datetime.utcnow()
                await session.commit()

    async def _checkpoint_stage(self, stage_name: str) -> None:
        """Mark a stage as *completed* (called after the stage finishes)."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.last_completed_stage = stage_name
                job.last_seen = datetime.utcnow()
                await session.commit()

    async def _mark_completed(self) -> None:
        """Mark the entire pipeline as COMPLETED."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.completed_at = datetime.utcnow()
                job.last_seen = datetime.utcnow()
                await session.commit()
