"""Recon pipeline: 7 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from sqlalchemy import select

from lib_webbh import Asset, CheckpointMixin, JobState, get_session, push_task, setup_logger
from lib_webbh.database import AssetSnapshot
from lib_webbh.diffing import compute_diff
from lib_webbh.scope import ScopeManager

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.tools import (
    Subfinder,
    Assetfinder,
    Chaos,
    AmassPassive,
    Sublist3r,
    Knockpy,
    AmassActive,
    Massdns,
    HttpxTool,
    SubjackTool,
    Webanalyze,
    Naabu,
    Katana,
    Hakrawler,
    Waybackurls,
    Gauplus,
    Paramspider,
)

logger = setup_logger("recon-pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[ReconTool]]


STAGES = [
    Stage("passive_discovery", [Subfinder, Assetfinder, Chaos, AmassPassive]),
    Stage("active_discovery", [Sublist3r, Knockpy, AmassActive]),
    Stage("liveness_dns", [Massdns, HttpxTool]),
    Stage("subdomain_takeover", [SubjackTool]),
    Stage("fingerprinting", [Webanalyze]),
    Stage("port_mapping", [Naabu]),
    Stage("deep_recon", [Katana, Hakrawler, Waybackurls, Gauplus, Paramspider]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


class Pipeline(CheckpointMixin):
    """Orchestrates the 7-stage recon pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str):
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    def _filter_stages(self, playbook: dict | None) -> list[Stage]:
        """Return only the stages enabled by the playbook config."""
        if not playbook or "stages" not in playbook:
            return list(STAGES)
        enabled_names = {
            s["name"] for s in playbook["stages"] if s.get("enabled", True)
        }
        return [stage for stage in STAGES if stage.name in enabled_names]

    async def run(
        self, target, scope_manager: ScopeManager, headers: dict | None = None,
        playbook: dict | None = None, rescan_scan_number: int | None = None,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        completed_phase = await self._get_resume_stage()
        start_index = 0

        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        stages = self._filter_stages(playbook)
        for stage in stages[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            stats = await self._run_stage(stage, target, scope_manager, headers)

            self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
            await push_task(f"events:{self.target_id}", {
                "event": "STAGE_COMPLETE",
                "stage": stage.name,
                "stats": stats,
            })
            await self._checkpoint_stage(stage.name)

        await self._mark_completed()

        if rescan_scan_number is not None:
            await self._compute_and_emit_diff(rescan_scan_number)

        await push_task(f"events:{self.target_id}", {
            "event": "PIPELINE_COMPLETE",
            "target_id": self.target_id,
        })

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
    ) -> dict:
        """Run all tools in a stage concurrently, return aggregated stats."""
        tools = [cls() for cls in stage.tool_classes]

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(f"Tool failed in {stage.name}", extra={"error": str(r)})
                continue
            aggregated["found"] += r.get("found", 0)
            aggregated["in_scope"] += r.get("in_scope", 0)
            aggregated["new"] += r.get("new", 0)

        return aggregated



    async def _compute_and_emit_diff(self, scan_number: int) -> None:
        """Compare current assets against the pre-rescan snapshot and emit diff."""
        async with get_session() as session:
            snapshot = (await session.execute(
                select(AssetSnapshot).where(
                    AssetSnapshot.target_id == self.target_id,
                    AssetSnapshot.scan_number == scan_number,
                )
            )).scalar_one_or_none()

            if snapshot is None:
                self.log.warning("No snapshot found for diff", extra={"scan_number": scan_number})
                return

            previous_hashes = snapshot.asset_hashes or {}

            assets = (await session.execute(
                select(Asset).where(Asset.target_id == self.target_id)
            )).scalars().all()
            current_hashes = {a.asset_value: f"{a.asset_type}:{a.source_tool}" for a in assets}

        diff = compute_diff(previous_hashes, current_hashes)

        if diff.has_changes:
            self.log.info("Recon diff detected", extra={
                "added": len(diff.added), "removed": len(diff.removed),
            })
            await push_task(f"events:{self.target_id}", {
                "event": "RECON_DIFF",
                "scan_number": scan_number,
                "added": diff.added,
                "removed": diff.removed,
                "unchanged_count": len(diff.unchanged),
            })
