"""Vuln scanner pipeline: 3 sequential stages with Nuclei triage routing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.nuclei_router import ROUTES, route_finding
from workers.vuln_scanner.tools import (
    CommixTool,
    HostHeaderTool,
    NucleiTool,
    PhpggcTool,
    SmugglerTool,
    SqlmapTool,
    SSRFmapTool,
    TplmapTool,
    XXEinjectorTool,
    YsoserialTool,
)

logger = setup_logger("vulnscan-pipeline")

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------


@dataclass
class Stage:
    name: str
    tool_classes: list[type[VulnScanTool]]


STAGES: list[Stage] = [
    Stage("nuclei_sweep", [NucleiTool]),
    Stage("active_injection", [
        SqlmapTool, TplmapTool, XXEinjectorTool, CommixTool, SSRFmapTool,
    ]),
    Stage("broad_injection_sweep", [
        SqlmapTool, TplmapTool, CommixTool, SSRFmapTool,
        SmugglerTool, HostHeaderTool, YsoserialTool, PhpggcTool,
    ]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


_rebuild_index()


# ---------------------------------------------------------------------------
# Tool name → class mapping for Stage 2 routing
# ---------------------------------------------------------------------------

TOOL_NAME_MAP: dict[str, type[VulnScanTool]] = {
    "sqlmap": SqlmapTool,
    "tplmap": TplmapTool,
    "xxeinjector": XXEinjectorTool,
    "commix": CommixTool,
    "ssrfmap": SSRFmapTool,
}


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Orchestrates the 3-stage vuln scanner pipeline with checkpointing."""

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

            if stage.name == "active_injection":
                stats = await self._run_active_injection(target, scope_manager, headers)
            elif stage.name == "broad_injection_sweep":
                stats = await self._run_stage(
                    stage, target, scope_manager, headers, scan_all=True
                )
            else:
                stats = await self._run_stage(stage, target, scope_manager, headers)

            self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
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

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
                **kwargs,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._aggregate_results(stage.name, results)

    async def _run_active_injection(
        self,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
    ) -> dict:
        """Stage 2: Query Nuclei findings, route to appropriate tools.

        Groups findings by tool, then runs each tool with its triaged
        findings concurrently.
        """
        aggregated = {"found": 0, "in_scope": 0, "new": 0}

        # Group findings by tool
        tool_findings: dict[str, list[tuple]] = {}
        for route in ROUTES:
            findings = await NucleiTool()._get_nuclei_findings(
                self.target_id, route.tag_filters
            )
            if findings:
                tool_findings.setdefault(route.tool_name, []).extend(findings)

        if not tool_findings:
            self.log.info("No triaged Nuclei findings for active injection")
            return aggregated

        # Launch each tool with its triaged findings
        tasks = []
        for tool_name, findings in tool_findings.items():
            tool_cls = TOOL_NAME_MAP.get(tool_name)
            if not tool_cls:
                self.log.warning(f"No tool class for '{tool_name}'")
                continue

            tool = tool_cls()
            tasks.append(
                tool.execute(
                    target=target,
                    scope_manager=scope_manager,
                    target_id=self.target_id,
                    container_name=self.container_name,
                    headers=headers,
                    triaged_findings=findings,
                )
            )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            aggregated = self._aggregate_results("active_injection", results)

        return aggregated

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_stats(aggregated: dict, result: dict) -> None:
        aggregated["found"] += result.get("found", result.get("findings", 0))
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
