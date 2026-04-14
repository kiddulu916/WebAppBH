# workers/cryptography/pipeline.py
from dataclasses import dataclass, field

import asyncio
from lib_webbh import push_task, setup_logger
from lib_webbh.pipeline_checkpoint import CheckpointMixin
from lib_webbh.scope import ScopeManager


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.tls_auditor import TlsAuditor
from .tools.padding_oracle_tester import PaddingOracleTester
from .tools.plaintext_leak_scanner import PlaintextLeakScanner
from .tools.algorithm_auditor import AlgorithmAuditor

STAGES = [
    Stage(name="tls_testing", section_id="4.9.1", tools=[TlsAuditor]),
    Stage(name="padding_oracle", section_id="4.9.2", tools=[PaddingOracleTester]),
    Stage(name="plaintext_transmission", section_id="4.9.3", tools=[PlaintextLeakScanner]),
    Stage(name="weak_crypto", section_id="4.9.4", tools=[AlgorithmAuditor]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}

logger = setup_logger("cryptography-pipeline")


class Pipeline(CheckpointMixin):
    """Orchestrates the 4-stage cryptography pipeline with checkpointing."""

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
        scope_manager: ScopeManager,
        headers: dict | None = None,
    ) -> dict:
        """Run all tools in a stage concurrently, return aggregated stats."""
        tools = [cls() for cls in stage.tools]

        tasks = [
            tool.execute(
                target_id=self.target_id,
                scope_manager=scope_manager,
                headers=headers,
                container_name=self.container_name,
            )
            for tool in tools
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {"found": 0, "vulnerable": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(f"Tool failed in {stage.name}", extra={"error": str(r)})
                continue
            aggregated["found"] += r.get("found", 0)
            aggregated["vulnerable"] += r.get("vulnerable", 0)

        return aggregated
