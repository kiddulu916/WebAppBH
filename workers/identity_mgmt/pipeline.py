"""Identity management pipeline: 5 sequential stages."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


from lib_webbh import push_task, setup_logger
from lib_webbh.pipeline_checkpoint import CheckpointMixin

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.tools import (
    RoleEnumerator,
    RegistrationTester,
    AccountProvisionTester,
    AccountEnumerator,
    UsernamePolicyTester,
)

logger = setup_logger("identity-pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[IdentityMgmtTool]]


STAGES = [
    Stage("role_definitions", [RoleEnumerator]),
    Stage("registration_process", [RegistrationTester]),
    Stage("account_provisioning", [AccountProvisionTester]),
    Stage("account_enumeration", [AccountEnumerator]),
    Stage("weak_username_policy", [UsernamePolicyTester]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


class Pipeline(CheckpointMixin):
    """Orchestrates the 5-stage identity management pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str):
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    def _filter_stages(self, playbook: dict | None) -> list[Stage]:
        """Return only the stages enabled by the playbook config."""
        from lib_webbh.playbooks import get_worker_stages
        worker_stages = get_worker_stages(playbook, "identity_mgmt")
        if worker_stages is None:
            return list(STAGES)
        if not worker_stages:
            return []
        enabled_names = {
            s["name"] for s in worker_stages if s.get("enabled", True)
        }
        return [stage for stage in STAGES if stage.name in enabled_names]

    async def run(
        self, target, scope_manager, headers: dict | None = None,
        playbook: dict | None = None,
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

        await push_task(f"events:{self.target_id}", {
            "event": "PIPELINE_COMPLETE",
            "target_id": self.target_id,
        })

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager,
        headers: dict | None = None,
    ) -> dict:
        """Run all tools in a stage concurrently, return aggregated stats."""
        tools = [cls() for cls in stage.tool_classes]

        # Load credentials for this target
        credentials = None
        for tool in tools:
            if hasattr(tool, 'get_tester_session'):
                credentials = await tool.get_tester_session(self.target_id)
                break

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                credentials=credentials,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {"found": 0, "inserted": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(f"Tool failed in {stage.name}", extra={"error": str(r)})
                continue
            aggregated["found"] += r.get("found", 0)
            aggregated["inserted"] += r.get("inserted", 0)

        return aggregated
