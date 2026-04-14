# tests/test_chain_worker_pipeline.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.pipeline import STAGES, Pipeline


def test_pipeline_has_five_stages():
    assert len(STAGES) == 5


def test_stage_names():
    names = [s.name for s in STAGES]
    assert names == ["data_collection", "chain_evaluation", "ai_chain_discovery", "chain_execution", "reporting"]


def test_stage_tool_classes():
    from workers.chain_worker.tools.findings_collector import FindingsCollector
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
    from workers.chain_worker.tools.ai_chain_discoverer import AIChainDiscoverer
    from workers.chain_worker.tools.chain_executor import ChainExecutor
    from workers.chain_worker.tools.chain_reporter import ChainReporter
    assert STAGES[0].tool_classes == [FindingsCollector]
    assert STAGES[1].tool_classes == [ChainEvaluator]
    assert STAGES[2].tool_classes == [AIChainDiscoverer]
    assert STAGES[3].tool_classes == [ChainExecutor]
    assert STAGES[4].tool_classes == [ChainReporter]


def test_pipeline_init():
    pipeline = Pipeline()
    assert pipeline is not None
