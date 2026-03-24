"""API testing pipeline: 4 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.tools import (
    FfufApiTool,
    GraphqlIntrospectTool,
    OpenapiParserTool,
    TrufflehogTool,
    # Stage 2
    JwtTool,
    OauthTesterTool,
    CorsScannerTool,
    # Stage 3
    IdorTesterTool,
    MassAssignTesterTool,
    NosqlmapTool,
    # Stage 4
    RateLimitTesterTool,
    GraphqlCopTool,
)

logger = setup_logger("api-pipeline")

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------


@dataclass
class Stage:
    name: str
    tool_classes: list[type[ApiTestTool]]


STAGES: list[Stage] = [
    Stage("api_discovery", [FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool]),
    Stage("auth_testing", [JwtTool, OauthTesterTool, CorsScannerTool]),
    Stage("injection_testing", [IdorTesterTool, MassAssignTesterTool, NosqlmapTool]),
    Stage("abuse_testing", [RateLimitTesterTool, GraphqlCopTool]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


_rebuild_index()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Orchestrates the 4-stage API testing pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str) -> None:
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        _rebuild_index()

        completed_phase = await self._get_completed_phase()
        start_index = 0

        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        for stage in STAGES[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            stats = await self._run_stage(stage, target, scope_manager, headers)

            self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
            await push_task(f"events:{self.target_id}", {
                "event": "STAGE_COMPLETE",
                "stage": stage.name,
                "stats": stats,
            })

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "PIPELINE_COMPLETE",
            "target_id": self.target_id,
        })

    # ------------------------------------------------------------------
    # Stage runners
    # ------------------------------------------------------------------

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run all tools in a stage concurrently."""
        tools = [cls() for cls in stage.tool_classes]

        async def _run_with_progress(tool):
            await push_task(f"events:{self.target_id}", {
                "event": "TOOL_PROGRESS", "container": self.container_name,
                "tool": tool.name, "progress": 0, "message": f"{tool.name} started",
            })
            result = await tool.execute(
                target=target, scope_manager=scope_manager,
                target_id=self.target_id, container_name=self.container_name,
                headers=headers, **kwargs,
            )
            msg = f"{tool.name} complete"
            if isinstance(result, dict):
                parts = [f"{k}={v}" for k, v in result.items() if isinstance(v, int)]
                if parts:
                    msg = f"{tool.name}: {', '.join(parts)}"
            await push_task(f"events:{self.target_id}", {
                "event": "TOOL_PROGRESS", "container": self.container_name,
                "tool": tool.name, "progress": 100, "message": msg,
            })
            return result

        tasks = [_run_with_progress(tool) for tool in tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._aggregate_results(stage.name, results)

    # ------------------------------------------------------------------
    # Checkpoint helpers
    # ------------------------------------------------------------------

    async def _get_completed_phase(self) -> str | None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
                JobState.status == "COMPLETED",
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            return job.current_phase if job else None

    async def _update_phase(self, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.current_phase = phase
                job.last_seen = datetime.utcnow()
                await session.commit()

    async def _mark_completed(self) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.last_seen = datetime.utcnow()
                await session.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_stats(aggregated: dict, result: dict) -> None:
        aggregated["found"] += result.get("found", 0)
        aggregated["in_scope"] += result.get("in_scope", 0)
        aggregated["new"] += result.get("new", 0)

    def _aggregate_results(self, stage_name: str, results: list) -> dict:
        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(
                    f"Tool failed in {stage_name}", extra={"error": str(r)}
                )
                continue
            self._merge_stats(aggregated, r)
        return aggregated
