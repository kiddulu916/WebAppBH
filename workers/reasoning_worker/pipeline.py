"""Reasoning worker pipeline — 3-stage LLM analysis."""
from __future__ import annotations

from lib_webbh import push_task, setup_logger
from lib_webbh.pipeline_checkpoint import CheckpointMixin

logger = setup_logger("reasoning_pipeline")

STAGES = ["finding_correlation", "impact_analysis", "chain_hypothesis"]
STAGE_INDEX = {name: i for i, name in enumerate(STAGES)}


class Pipeline(CheckpointMixin):
    def __init__(self, target_id: int, container_name: str):
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    async def run(self, session) -> int:
        from workers.reasoning_worker.analyzer import (
            query_target_context,
            chunk_vulns,
            parse_llm_response,
            _build_insight,
        )
        from lib_webbh.llm_client import LLMClient
        from lib_webbh.prompts.reasoning import REASONING_SYSTEM, build_reasoning_prompt

        completed_phase = await self._get_resume_stage()
        start_index = STAGE_INDEX.get(completed_phase, -1) + 1 if completed_phase else 0

        # Stage 1: finding_correlation
        target_info, vulns = {}, []
        if start_index <= 0:
            await self._update_phase("finding_correlation")
            target_info, vulns = await query_target_context(session, self.target_id)
            await push_task(f"events:{self.target_id}", {
                "event": "STAGE_COMPLETE",
                "stage": "finding_correlation",
                "stats": {"vulns": len(vulns)},
            })
            await self._checkpoint_stage("finding_correlation")

        # Stage 2: impact_analysis
        insights_data: list[tuple[dict, str]] = []
        if start_index <= 1:
            await self._update_phase("impact_analysis")
            if vulns:
                client = LLMClient()
                for batch in chunk_vulns(vulns, batch_size=10):
                    prompt = build_reasoning_prompt(target_info, batch)
                    response = await client.generate(
                        prompt=prompt,
                        system=REASONING_SYSTEM,
                        json_mode=True,
                        temperature=0.2,
                    )
                    for raw in parse_llm_response(response.text):
                        if "vulnerability_id" in raw:
                            insights_data.append((raw, response.text))
            await push_task(f"events:{self.target_id}", {
                "event": "STAGE_COMPLETE",
                "stage": "impact_analysis",
                "stats": {"analyzed": len(insights_data)},
            })
            await self._checkpoint_stage("impact_analysis")

        # Stage 3: chain_hypothesis
        total = 0
        if start_index <= 2:
            await self._update_phase("chain_hypothesis")
            for raw, raw_text in insights_data:
                insight = _build_insight(self.target_id, raw, raw_text)
                session.add(insight)
                total += 1
            if total:
                await session.commit()
            await push_task(f"events:{self.target_id}", {
                "event": "STAGE_COMPLETE",
                "stage": "chain_hypothesis",
                "stats": {"insights": total},
            })
            await self._checkpoint_stage("chain_hypothesis")

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "PIPELINE_COMPLETE",
            "target_id": self.target_id,
        })
        return total
