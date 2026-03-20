import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainViability, EvaluationResult, ChainResult, TargetFindings
from workers.chain_worker.registry import BaseChainTemplate, register_chain, clear_registry, save_registry, restore_registry


def test_tool_attributes():
    tool = ChainEvaluator()
    assert tool.name == "chain_evaluator"
    assert tool.weight_class == WeightClass.LIGHT


@pytest.mark.anyio
async def test_evaluate_buckets():
    saved = save_registry()
    clear_registry()

    @register_chain
    class V(BaseChainTemplate):
        name = "v1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            return ChainResult(success=True, steps=[], poc="t", chain_name=self.name)

    @register_chain
    class P(BaseChainTemplate):
        name = "p1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["half"], missing_preconditions=["other"])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    @register_chain
    class N(BaseChainTemplate):
        name = "n1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    evaluator = ChainEvaluator()
    buckets = await evaluator.evaluate_all(findings)
    assert len(buckets["viable"]) == 1
    assert len(buckets["partial"]) == 1
    assert len(buckets["not_viable"]) == 1
    restore_registry(saved)
