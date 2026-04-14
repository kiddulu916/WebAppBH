"""Config management pipeline: 11 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


from lib_webbh import push_task, setup_logger
from lib_webbh.pipeline_checkpoint import CheckpointMixin
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.tools import (
    NetworkConfigTester,
    PlatformFingerprinter,
    FileExtensionTester,
    BackupFileFinder,
    FfufTool,
    ApiDiscoveryTool,
    HttpMethodTester,
    HstsTester,
    RpcTester,
    FileInclusionTester,
    SubdomainTakeoverChecker,
    CloudStorageAuditor,
)

logger = setup_logger("config-mgmt-pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[ConfigMgmtTool]]


STAGES = [
    Stage("network_config", [NetworkConfigTester]),
    Stage("platform_config", [PlatformFingerprinter]),
    Stage("file_extension_handling", [FileExtensionTester]),
    Stage("backup_files", [BackupFileFinder, FfufTool]),
    Stage("api_discovery", [ApiDiscoveryTool]),
    Stage("http_methods", [HttpMethodTester]),
    Stage("hsts_testing", [HstsTester]),
    Stage("rpc_testing", [RpcTester]),
    Stage("file_inclusion", [FileInclusionTester]),
    Stage("subdomain_takeover", [SubdomainTakeoverChecker]),
    Stage("cloud_storage", [CloudStorageAuditor]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


class Pipeline(CheckpointMixin):
    """Orchestrates the 11-stage config management pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str):
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    async def run(
        self, target, scope_manager: ScopeManager, headers: dict | None = None
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
            await self._checkpoint_stage(stage.name)

        await self._mark_completed()

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
