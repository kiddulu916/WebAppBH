from __future__ import annotations

from typing import Any

from lib_webbh import setup_logger

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainViability, EvaluationResult, TargetFindings
from workers.chain_worker.registry import get_registry

logger = setup_logger("chain_evaluator")


class ChainEvaluator(ChainTestTool):
    name = "chain_evaluator"
    weight_class = WeightClass.LIGHT

    async def evaluate_all(
        self, findings: TargetFindings,
    ) -> dict[str, list[tuple[str, EvaluationResult]]]:
        registry = get_registry()
        buckets: dict[str, list[tuple[str, EvaluationResult]]] = {
            "viable": [], "awaiting_accounts": [], "partial": [], "not_viable": [],
        }
        for name, chain in registry.items():
            try:
                result = await chain.evaluate(findings)
            except Exception as exc:
                logger.warning("Chain evaluate failed", extra={"chain": name, "error": str(exc)})
                continue
            buckets[result.viability.value].append((name, result))

        logger.info("Evaluation complete", extra={
            "target_id": findings.target_id,
            "viable": len(buckets["viable"]),
            "awaiting_accounts": len(buckets["awaiting_accounts"]),
            "partial": len(buckets["partial"]),
            "not_viable": len(buckets["not_viable"]),
        })
        return buckets

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        findings: TargetFindings = kwargs["_findings"]
        buckets = await self.evaluate_all(findings)
        kwargs["_buckets"] = buckets
        return {
            "viable": len(buckets["viable"]),
            "awaiting_accounts": len(buckets["awaiting_accounts"]),
            "partial": len(buckets["partial"]),
            "not_viable": len(buckets["not_viable"]),
        }
