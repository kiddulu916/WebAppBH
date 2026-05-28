# workers/chain_worker/pipeline.py
"""Chain testing pipeline: 4 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import Campaign, ChainFinding, JobState, Target, Vulnerability
from lib_webbh.messaging import push_task
from sqlalchemy import select, update

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import get_semaphore
from workers.chain_worker.tools.ai_chain_discoverer import AIChainDiscoverer
from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
from workers.chain_worker.tools.chain_executor import ChainExecutor
from workers.chain_worker.tools.chain_reporter import ChainReporter
from workers.chain_worker.tools.findings_collector import FindingsCollector

logger = setup_logger("chain_pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[ChainTestTool]]


STAGES: list[Stage] = [
    Stage("data_collection", [FindingsCollector]),
    Stage("chain_evaluation", [ChainEvaluator]),
    Stage("ai_chain_discovery", [AIChainDiscoverer]),
    Stage("chain_execution", [ChainExecutor]),
    Stage("reporting", [ChainReporter]),
]

STAGE_INDEX: dict[str, int] = {s.name: i for i, s in enumerate(STAGES)}


async def _promote_chain_only_findings(target_id: int) -> int:
    """Promote chain_only=True vulns that appear in a high/critical ChainFinding.

    Returns the count of promoted findings.
    """
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()

        if not target or not target.campaign_id:
            return 0

        campaign = (await session.execute(
            select(Campaign).where(Campaign.id == target.campaign_id)
        )).scalar_one_or_none()

        conditional = (campaign.conditional_stages or {}) if campaign else {}
        chain_exception_stages = {
            stage for stage, rule in conditional.items()
            if rule.get("chain_exception")
        }
        if not chain_exception_stages:
            return 0

        chains = (await session.execute(
            select(ChainFinding).where(
                ChainFinding.target_id == target_id,
                ChainFinding.severity.in_(["high", "critical"]),
            )
        )).scalars().all()

        qualifying_vuln_ids: set[int] = set()
        for chain in chains:
            qualifying_vuln_ids.add(chain.entry_vulnerability_id)
            linked = chain.linked_vulnerability_ids or {}
            for vid in linked.get("ids", []):
                try:
                    qualifying_vuln_ids.add(int(vid))
                except (TypeError, ValueError):
                    logger.warning("Skipping non-integer linked_vulnerability_id", value=repr(vid), chain_id=chain.id)

        if not qualifying_vuln_ids:
            return 0

        result = await session.execute(
            update(Vulnerability)
            .where(
                Vulnerability.id.in_(qualifying_vuln_ids),
                Vulnerability.chain_only.is_(True),
            )
            .values(chain_only=False)
        )
        await session.commit()
        return result.rowcount


class Pipeline:
    async def run(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str,
    ) -> None:
        log = logger.bind(target_id=target_id)
        start_index = await self._get_resume_index(target_id, container_name)
        kwargs: dict[str, Any] = {}

        for i in range(start_index, len(STAGES)):
            stage = STAGES[i]
            log.info("Starting stage", extra={"stage": stage.name})
            tools = [cls() for cls in stage.tool_classes]
            tasks = []
            for tool in tools:
                sem = get_semaphore(tool.weight_class)

                async def _run(t: ChainTestTool = tool, s: Any = sem) -> dict:
                    async with s:
                        await push_task(f"events:{target_id}", {
                            "event": "TOOL_PROGRESS", "container": container_name,
                            "tool": t.name, "progress": 0, "message": f"{t.name} started",
                        })
                        result = await t.execute(
                            target=target, scope_manager=scope_manager,
                            target_id=target_id, container_name=container_name,
                            **kwargs,
                        )
                        msg = f"{t.name} complete"
                        if isinstance(result, dict):
                            parts = [f"{k}={v}" for k, v in result.items() if isinstance(v, int)]
                            if parts:
                                msg = f"{t.name}: {', '.join(parts)}"
                        await push_task(f"events:{target_id}", {
                            "event": "TOOL_PROGRESS", "container": container_name,
                            "tool": t.name, "progress": 100, "message": msg,
                        })
                        return result

                tasks.append(_run())

            results = await asyncio.gather(*tasks, return_exceptions=True)
            stats: dict[str, Any] = {}
            for r in results:
                if isinstance(r, Exception):
                    log.error("Tool failed", extra={"stage": stage.name, "error": str(r)})
                elif isinstance(r, dict):
                    stats.update(r)

            if stage.name == "chain_execution":
                promoted = await _promote_chain_only_findings(target_id)
                if promoted:
                    log.info("Promoted chain_only findings", count=promoted)

            await self._update_phase(target_id, container_name, stage.name)
            await push_task(f"events:{target_id}", {
                "event": "STAGE_COMPLETE", "stage": stage.name, "stats": stats,
            })
            log.info("Stage complete", extra={"stage": stage.name, "stats": stats})

        await self._mark_completed(target_id, container_name)
        await push_task(f"events:{target_id}", {"event": "PIPELINE_COMPLETE", "worker": "chain_worker"})

    async def _get_resume_index(self, target_id: int, container_name: str) -> int:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row and row.current_phase and row.status != "COMPLETED":
                idx = STAGE_INDEX.get(row.current_phase, -1)
                return idx + 1
        return 0

    async def _update_phase(self, target_id: int, container_name: str, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.current_phase = phase
                row.last_seen = datetime.utcnow()
                await session.commit()

    async def _mark_completed(self, target_id: int, container_name: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.status = "COMPLETED"
                row.last_seen = datetime.utcnow()
                await session.commit()
