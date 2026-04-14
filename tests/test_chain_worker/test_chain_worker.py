import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_concurrency_semaphores():
    from workers.chain_worker.concurrency import WeightClass, get_semaphore
    sem = get_semaphore(WeightClass.HEAVY)
    assert isinstance(sem, asyncio.BoundedSemaphore)


def test_chain_registry():
    from workers.chain_worker.registry import (
        BaseChainTemplate, ChainContext, get_registry, register_chain,
    )
    from workers.chain_worker.models import (
        ChainResult, ChainViability, EvaluationResult, TargetFindings,
    )
    assert hasattr(BaseChainTemplate, "evaluate")
    assert hasattr(BaseChainTemplate, "execute")
    assert hasattr(ChainViability, "VIABLE")
    assert hasattr(ChainViability, "PARTIAL")
    assert hasattr(ChainViability, "NOT_VIABLE")
    assert hasattr(ChainViability, "AWAITING_ACCOUNTS")


def test_all_chain_categories_importable():
    import workers.chain_worker.chains.auth_session  # noqa: F401
    import workers.chain_worker.chains.injection_execution  # noqa: F401
    import workers.chain_worker.chains.ssrf_infrastructure  # noqa: F401
    import workers.chain_worker.chains.xss_client_side  # noqa: F401
    import workers.chain_worker.chains.file_processing  # noqa: F401
    import workers.chain_worker.chains.header_protocol  # noqa: F401
    import workers.chain_worker.chains.access_control  # noqa: F401
    import workers.chain_worker.chains.bypass  # noqa: F401
    import workers.chain_worker.chains.platform_protocol  # noqa: F401
    from workers.chain_worker.registry import get_registry
    registry = get_registry()
    assert len(registry) > 0


def test_chain_categories():
    import workers.chain_worker.chains.auth_session  # noqa: F401
    import workers.chain_worker.chains.injection_execution  # noqa: F401
    import workers.chain_worker.chains.ssrf_infrastructure  # noqa: F401
    import workers.chain_worker.chains.xss_client_side  # noqa: F401
    import workers.chain_worker.chains.file_processing  # noqa: F401
    import workers.chain_worker.chains.header_protocol  # noqa: F401
    import workers.chain_worker.chains.access_control  # noqa: F401
    import workers.chain_worker.chains.bypass  # noqa: F401
    import workers.chain_worker.chains.platform_protocol  # noqa: F401
    from workers.chain_worker.registry import get_registry
    registry = get_registry()
    categories = {}
    for chain in registry.values():
        categories.setdefault(chain.category, 0)
        categories[chain.category] += 1
    assert "auth_session" in categories
    assert categories["auth_session"] == 22


def test_pipeline_stages():
    from workers.chain_worker.pipeline import STAGES
    assert len(STAGES) == 5
    assert STAGES[0].name == "data_collection"
    assert STAGES[1].name == "chain_evaluation"
    assert STAGES[2].name == "ai_chain_discovery"
    assert STAGES[3].name == "chain_execution"
    assert STAGES[4].name == "reporting"


def test_pipeline_tools_exist():
    from workers.chain_worker.pipeline import STAGES
    from workers.chain_worker.tools.findings_collector import FindingsCollector
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
    from workers.chain_worker.tools.chain_executor import ChainExecutor
    from workers.chain_worker.tools.chain_reporter import ChainReporter
    stage_tools = {stage.name: stage.tool_classes for stage in STAGES}
    assert FindingsCollector in stage_tools["data_collection"]
    assert ChainEvaluator in stage_tools["chain_evaluation"]
    assert ChainExecutor in stage_tools["chain_execution"]
    assert ChainReporter in stage_tools["reporting"]


def test_tool_weight_classes():
    from workers.chain_worker.tools.findings_collector import FindingsCollector
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
    from workers.chain_worker.tools.chain_executor import ChainExecutor
    from workers.chain_worker.tools.chain_reporter import ChainReporter
    from workers.chain_worker.concurrency import WeightClass
    assert FindingsCollector.weight_class == WeightClass.LIGHT
    assert ChainEvaluator.weight_class == WeightClass.LIGHT
    assert ChainExecutor.weight_class == WeightClass.HEAVY
    assert ChainReporter.weight_class == WeightClass.LIGHT


def test_base_tool_abstract():
    from abc import ABC
    from workers.chain_worker.base_tool import ChainTestTool
    assert issubclass(ChainTestTool, ABC)
    with pytest.raises(TypeError):
        ChainTestTool()


@pytest.mark.anyio
async def test_findings_collector_execute():
    from workers.chain_worker.tools.findings_collector import FindingsCollector
    tool = FindingsCollector()
    target = MagicMock()
    scope_mgr = MagicMock()
    kwargs = {}
    with patch("workers.chain_worker.tools.findings_collector.get_session") as mock_session:
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_session.return_value = mock_ctx
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_ctx.execute = AsyncMock(return_value=mock_result)
        result = await tool.execute(
            target=target, scope_manager=scope_mgr,
            target_id=1, container_name="test", **kwargs,
        )
        assert "vulns" in result
        assert "assets" in result


@pytest.mark.anyio
async def test_chain_evaluator_execute():
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
    from workers.chain_worker.models import TargetFindings
    tool = ChainEvaluator()
    target = MagicMock()
    scope_mgr = MagicMock()
    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[],
        parameters=[], observations=[], locations=[],
        test_accounts=None,
    )
    kwargs = {"_findings": findings}
    with patch("workers.chain_worker.tools.chain_evaluator.get_registry", return_value={}):
        result = await tool.execute(
            target=target, scope_manager=scope_mgr,
            target_id=1, container_name="test", **kwargs,
        )
        assert "viable" in result
        assert "not_viable" in result


@pytest.mark.anyio
async def test_chain_executor_execute_no_chains():
    from workers.chain_worker.tools.chain_executor import ChainExecutor
    from workers.chain_worker.models import TargetFindings
    tool = ChainExecutor()
    target = MagicMock()
    scope_mgr = MagicMock()
    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[],
        parameters=[], observations=[], locations=[],
        test_accounts=None,
    )
    kwargs = {
        "_findings": findings,
        "_buckets": {"viable": []},
    }
    result = await tool.execute(
        target=target, scope_manager=scope_mgr,
        target_id=1, container_name="test", **kwargs,
    )
    assert result["executed"] == 0


@pytest.mark.anyio
async def test_chain_reporter_no_results():
    from workers.chain_worker.tools.chain_reporter import ChainReporter
    from workers.chain_worker.models import TargetFindings
    tool = ChainReporter()
    target = MagicMock()
    scope_mgr = MagicMock()
    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[],
        parameters=[], observations=[], locations=[],
        test_accounts=None,
    )
    kwargs = {"_findings": findings, "_chain_results": []}
    result = await tool.execute(
        target=target, scope_manager=scope_mgr,
        target_id=1, container_name="test", **kwargs,
    )
    assert result == {"reported": 0}
