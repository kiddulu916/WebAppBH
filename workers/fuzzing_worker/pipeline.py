"""Fuzzing pipeline: 4 sequential stages with tool chaining and permutation handoff."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.permutation import extract_prefix, generate_permutations
from workers.fuzzing_worker.tools import (
    ArjunTool,
    ExtensionFuzzTool,
    FeroxbusterTool,
    FfufTool,
    HeaderFuzzTool,
    VhostFuzzTool,
)

logger = setup_logger("fuzzing-pipeline")

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------


@dataclass
class Stage:
    name: str
    tool_classes: list[type[FuzzingTool]]


STAGES: list[Stage] = [
    Stage("dir_fuzzing",     [FfufTool, FeroxbusterTool, ExtensionFuzzTool]),
    Stage("vhost_fuzzing",   [VhostFuzzTool]),
    Stage("param_discovery", [ArjunTool]),
    Stage("header_fuzzing",  [HeaderFuzzTool]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    """Rebuild the STAGE_INDEX mapping from the current STAGES list."""
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


# Build once at import time.
_rebuild_index()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

PERMUTATION_BATCH_SIZE = 100


class Pipeline:
    """Orchestrates the 4-stage fuzzing pipeline with checkpointing."""

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
                "event": "stage_complete",
                "stage": stage.name,
                "stats": stats,
            })

        # Post-pipeline permutation handoff
        await self._run_permutation_handoff(target)

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "pipeline_complete",
            "target_id": self.target_id,
        })

    # ------------------------------------------------------------------
    # Stage runner
    # ------------------------------------------------------------------

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run all tools in a stage. dir_fuzzing uses chained execution; others run concurrently."""
        if stage.name == "dir_fuzzing":
            return await self._run_dir_fuzzing_stage(
                stage, target, scope_manager, headers, **kwargs
            )

        # All other stages: run tools concurrently
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

    # ------------------------------------------------------------------
    # Special dir_fuzzing stage (chained execution)
    # ------------------------------------------------------------------

    async def _run_dir_fuzzing_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run dir_fuzzing tools sequentially with shared state.

        1. ffuf first -- populates shared_state with discovered_dirs
        2. feroxbuster -- receives discovered_dirs from shared_state
        3. extension fuzz -- runs last
        """
        shared_state: dict = {}
        aggregated = {"found": 0, "in_scope": 0, "new": 0}

        # 1. ffuf
        ffuf = FfufTool()
        try:
            result = await ffuf.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
                shared_state=shared_state,
                **kwargs,
            )
            self._merge_stats(aggregated, result)
        except Exception as exc:
            self.log.error(
                f"Tool failed in {stage.name} (ffuf)", extra={"error": str(exc)}
            )

        # 2. feroxbuster with discovered dirs from ffuf
        feroxbuster = FeroxbusterTool()
        try:
            result = await feroxbuster.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
                discovered_dirs=shared_state.get("discovered_dirs", []),
                **kwargs,
            )
            self._merge_stats(aggregated, result)
        except Exception as exc:
            self.log.error(
                f"Tool failed in {stage.name} (feroxbuster)",
                extra={"error": str(exc)},
            )

        # 3. extension fuzz
        ext_fuzz = ExtensionFuzzTool()
        try:
            result = await ext_fuzz.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
                **kwargs,
            )
            self._merge_stats(aggregated, result)
        except Exception as exc:
            self.log.error(
                f"Tool failed in {stage.name} (extension_fuzz)",
                extra={"error": str(exc)},
            )

        return aggregated

    # ------------------------------------------------------------------
    # Permutation handoff
    # ------------------------------------------------------------------

    async def _run_permutation_handoff(self, target) -> None:
        """Generate subdomain permutations from discovered assets and push to recon queue."""
        base_domain = getattr(target, "base_domain", None)
        if not base_domain:
            self.log.warning("No base_domain on target; skipping permutation handoff")
            return

        # Query all domain assets for this target
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == self.target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            self.log.info("No domain assets found; skipping permutation handoff")
            return

        # Extract prefixes
        prefixes: list[str] = []
        existing: set[str] = set(domains)
        for fqdn in domains:
            prefix = extract_prefix(fqdn, base_domain)
            if prefix:
                prefixes.append(prefix)

        if not prefixes:
            self.log.info("No prefixes extracted; skipping permutation handoff")
            return

        permutations = generate_permutations(prefixes, base_domain, existing)

        if not permutations:
            self.log.info("No new permutations generated")
            return

        self.log.info(
            f"Generated {len(permutations)} permutations, pushing in batches",
            extra={"prefix_count": len(prefixes)},
        )

        # Push in batches of PERMUTATION_BATCH_SIZE
        for i in range(0, len(permutations), PERMUTATION_BATCH_SIZE):
            batch = permutations[i : i + PERMUTATION_BATCH_SIZE]
            await push_task("recon_queue", {
                "target_id": self.target_id,
                "source": "fuzzing_permutation",
                "domains": batch,
            })

    # ------------------------------------------------------------------
    # Checkpoint helpers
    # ------------------------------------------------------------------

    async def _get_completed_phase(self) -> str | None:
        """Query job_state for the last completed phase."""
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
        """Update job_state with current phase."""
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
        """Mark the job as COMPLETED."""
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
        """Merge a single tool result into the aggregated stats dict."""
        aggregated["found"] += result.get("found", 0)
        aggregated["in_scope"] += result.get("in_scope", 0)
        aggregated["new"] += result.get("new", 0)

    def _aggregate_results(self, stage_name: str, results: list) -> dict:
        """Aggregate results from asyncio.gather, handling exceptions."""
        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(
                    f"Tool failed in {stage_name}", extra={"error": str(r)}
                )
                continue
            self._merge_stats(aggregated, r)
        return aggregated
