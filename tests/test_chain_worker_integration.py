# tests/test_chain_worker_integration.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.models import TargetFindings
from workers.chain_worker.tools.findings_collector import FindingsCollector
from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
from workers.chain_worker.tools.chain_executor import ChainExecutor
from workers.chain_worker.tools.chain_reporter import ChainReporter
from workers.chain_worker.pipeline import STAGES


def test_pipeline_stage_order():
    assert STAGES[0].name == "data_collection"
    assert STAGES[1].name == "chain_evaluation"
    assert STAGES[2].name == "ai_chain_discovery"
    assert STAGES[3].name == "chain_execution"
    assert STAGES[4].name == "reporting"


def test_all_tools_importable():
    assert FindingsCollector().name == "findings_collector"
    assert ChainEvaluator().name == "chain_evaluator"
    assert ChainExecutor().name == "chain_executor"
    assert ChainReporter().name == "chain_reporter"


@pytest.mark.anyio
async def test_evaluator_empty_findings():
    import workers.chain_worker.chains  # noqa: F401
    from workers.chain_worker.registry import get_registry

    findings = TargetFindings(
        target_id=999, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    evaluator = ChainEvaluator()
    buckets = await evaluator.evaluate_all(findings)
    assert len(buckets["viable"]) == 0
    total = len(buckets["not_viable"]) + len(buckets["partial"]) + len(buckets["awaiting_accounts"])
    assert total == len(get_registry())
