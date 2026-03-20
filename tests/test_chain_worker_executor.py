# tests/test_chain_worker_executor.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ["CHAIN_STEP_DELAY_MS"] = "1"

import pytest
from datetime import datetime
from workers.chain_worker.tools.chain_executor import ChainExecutor
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainViability, ChainResult, ChainStep, EvaluationResult, TargetFindings
from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain, clear_registry


def test_tool_attributes():
    tool = ChainExecutor()
    assert tool.name == "chain_executor"
    assert tool.weight_class == WeightClass.HEAVY


@pytest.mark.anyio
async def test_run_viable_chains(tmp_path):
    clear_registry()

    @register_chain
    class S(BaseChainTemplate):
        name = "s1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            return ChainResult(
                success=True,
                steps=[ChainStep(action="a", target="t", result="ok", timestamp=datetime.now().isoformat())],
                poc="curl exploit", chain_name=self.name,
            )

    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    viable = [("s1", EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"], matched_findings={"v": 1}))]
    executor = ChainExecutor()
    results = await executor.run_chains(
        viable_chains=viable, findings=findings, target_id=1,
        scope_manager=None, evidence_dir=str(tmp_path),
    )
    assert len(results) == 1
    assert results[0].success is True
    clear_registry()


@pytest.mark.anyio
async def test_failed_chain_continues(tmp_path):
    clear_registry()

    @register_chain
    class F(BaseChainTemplate):
        name = "f1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            raise RuntimeError("broke")

    @register_chain
    class O(BaseChainTemplate):
        name = "o1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            return ChainResult(success=True, steps=[], poc="ok", chain_name=self.name)

    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    viable = [
        ("f1", EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])),
        ("o1", EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])),
    ]
    executor = ChainExecutor()
    results = await executor.run_chains(
        viable_chains=viable, findings=findings, target_id=1,
        scope_manager=None, evidence_dir=str(tmp_path),
    )
    assert len(results) == 2
    assert results[0].success is False
    assert results[1].success is True
    clear_registry()
