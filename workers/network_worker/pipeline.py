# workers/network_worker/pipeline.py
"""Network testing pipeline: 4 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.tools import (
    NaabuTool,
    NmapTool,
    BannerGrabTool,
    MedusaTool,
    LdapInjectionTool,
    MsfCheckTool,
)

logger = setup_logger("network-pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[NetworkTestTool]]


STAGES: list[Stage] = [
    Stage("port_discovery", [NaabuTool]),
    Stage("service_scan", [NmapTool, BannerGrabTool]),
    Stage("credential_test", [MedusaTool, LdapInjectionTool]),
    Stage("exploit_verify", [MsfCheckTool]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


_rebuild_index()


class Pipeline:
    """Orchestrates the 4-stage network testing pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str) -> None:
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    async def run(
        self,
        target,
        scope_manager: ScopeManager,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        _rebuild_index()

        # Load oos_attacks once for the whole pipeline
        from workers.network_worker.tools.naabu_tool import NaabuTool

        loader = NaabuTool()
        oos_attacks = await loader._load_oos_attacks(self.target_id)

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

            stats = await self._run_stage(
                stage, target, scope_manager, oos_attacks=oos_attacks,
            )

            self.log.info(
                f"Stage complete: {stage.name}", extra={"stats": stats},
            )
            await push_task(f"events:{self.target_id}", {
                "event": "stage_complete",
                "stage": stage.name,
                "stats": stats,
            })

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "pipeline_complete",
            "target_id": self.target_id,
        })

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        **kwargs,
    ) -> dict:
        """Run all tools in a stage concurrently."""
        tools = [cls() for cls in stage.tool_classes]

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                **kwargs,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._aggregate_results(stage.name, results)

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
                job.last_seen = datetime.now(timezone.utc)
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
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

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
