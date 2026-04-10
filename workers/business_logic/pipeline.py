# workers/business_logic/pipeline.py
from dataclasses import dataclass, field

import asyncio
from datetime import datetime
from sqlalchemy import select
from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.business_validation_tester import BusinessValidationTester
from .tools.request_forgery_tester import RequestForgeryTester
from .tools.integrity_tester import IntegrityTester
from .tools.timing_analyzer import TimingAnalyzer
from .tools.rate_limit_tester import RateLimitTester
from .tools.workflow_bypass_tester import WorkflowBypassTester
from .tools.misuse_tester import MisuseTester
from .tools.file_type_tester import FileTypeTester
from .tools.malicious_upload_tester import MaliciousUploadTester

STAGES = [
    Stage(name="data_validation", section_id="4.10.1", tools=[BusinessValidationTester]),
    Stage(name="request_forgery", section_id="4.10.2", tools=[RequestForgeryTester]),
    Stage(name="integrity_checks", section_id="4.10.3", tools=[IntegrityTester]),
    Stage(name="process_timing", section_id="4.10.4", tools=[TimingAnalyzer]),
    Stage(name="rate_limiting", section_id="4.10.5", tools=[RateLimitTester]),
    Stage(name="workflow_bypass", section_id="4.10.6", tools=[WorkflowBypassTester]),
    Stage(name="application_misuse", section_id="4.10.7", tools=[MisuseTester]),
    Stage(name="file_upload_validation", section_id="4.10.8", tools=[FileTypeTester]),
    Stage(name="malicious_file_upload", section_id="4.10.9", tools=[MaliciousUploadTester]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}

logger = setup_logger("business-logic-pipeline")


class Pipeline:
    """Orchestrates the 9-stage business logic pipeline with checkpointing."""

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
        completed_phase = await self._get_completed_phase()
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
                job.last_seen = datetime.utcnow()
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
                job.last_seen = datetime.utcnow()
                await session.commit()
