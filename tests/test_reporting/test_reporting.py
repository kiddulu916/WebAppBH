import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_reporting_models():
    from workers.reporting_worker.models import (
        AffectedAsset, FindingGroup, ReportContext, ReportData,
        SummaryStats, sanitize_filename,
    )
    assert sanitize_filename("test/vuln:name") == "test_vuln_name"
    stats = SummaryStats(critical=1, high=2, medium=3)
    assert stats.total_findings == 6


def test_data_gatherer_import():
    from workers.reporting_worker.data_gatherer import gather_report_data
    assert callable(gather_report_data)


def test_deduplicator_import():
    from workers.reporting_worker.deduplicator import deduplicate_and_enrich
    assert callable(deduplicate_and_enrich)


def test_pipeline_stages():
    from workers.reporting_worker.pipeline import STAGES
    assert len(STAGES) == 4
    assert STAGES[0].name == "data_gathering"
    assert STAGES[1].name == "deduplication"
    assert STAGES[2].name == "rendering"
    assert STAGES[3].name == "export"


def test_format_renderers():
    from workers.reporting_worker.pipeline import FORMAT_RENDERERS
    assert "hackerone_md" in FORMAT_RENDERERS
    assert "bugcrowd_md" in FORMAT_RENDERERS
    assert "executive_pdf" in FORMAT_RENDERERS
    assert "technical_pdf" in FORMAT_RENDERERS


def test_base_renderer_abstract():
    from abc import ABC
    from workers.reporting_worker.base_renderer import BaseRenderer
    assert issubclass(BaseRenderer, ABC)


def test_markdown_renderer():
    from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer
    renderer = MarkdownRenderer()
    assert hasattr(renderer, "render")


def test_technical_renderer():
    from workers.reporting_worker.renderers.technical_renderer import TechnicalRenderer
    renderer = TechnicalRenderer()
    assert hasattr(renderer, "render")


def test_executive_renderer():
    from workers.reporting_worker.renderers.executive_renderer import ExecutiveRenderer
    renderer = ExecutiveRenderer()
    assert hasattr(renderer, "render")


@pytest.mark.anyio
async def test_gather_report_data_mock():
    from workers.reporting_worker.data_gatherer import gather_report_data
    mock_target = MagicMock()
    mock_target.company_name = "Test Corp"
    mock_target.base_domain = "test.com"
    mock_target.target_profile = {}
    mock_target.id = 1
    with patch("workers.reporting_worker.data_gatherer.get_session") as mock_session:
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_session.return_value = mock_ctx
        mock_execute_result = MagicMock()
        mock_execute_result.scalar_one.return_value = mock_target
        mock_execute_result.scalars.return_value.all.return_value = []
        mock_ctx.execute = AsyncMock(return_value=mock_execute_result)
        with patch("workers.reporting_worker.data_gatherer._scan_screenshots", return_value={}):
            result = await gather_report_data(target_id=1)
            assert result.company_name == "Test Corp"
            assert result.base_domain == "test.com"


@pytest.mark.anyio
async def test_pipeline_run_mock():
    from workers.reporting_worker.pipeline import Pipeline, FORMAT_RENDERERS
    from workers.reporting_worker.models import ReportData, SummaryStats
    with patch("workers.reporting_worker.pipeline.logger") as mock_logger:
        mock_logger.bind.return_value = MagicMock()
        pipeline = Pipeline()
        with patch("workers.reporting_worker.pipeline.gather_report_data", new_callable=AsyncMock) as mock_gather:
            mock_ctx = MagicMock()
            mock_ctx.vulnerabilities = []
            mock_ctx.assets = []
            mock_ctx.locations = []
            mock_ctx.observations = []
            mock_ctx.cloud_assets = []
            mock_ctx.api_schemas = []
            mock_ctx.screenshot_map = {}
            mock_ctx.company_name = "Test Corp"
            mock_ctx.base_domain = "test.com"
            mock_gather.return_value = mock_ctx
            with patch("workers.reporting_worker.pipeline.deduplicate_and_enrich") as mock_dedup:
                mock_data = ReportData(
                    company_name="Test Corp",
                    base_domain="test.com",
                    finding_groups=[],
                    summary_stats=SummaryStats(),
                    generation_date="2026-03-31",
                    platform="hackerone",
                    formats=["hackerone_md"],
                )
                mock_dedup.return_value = mock_data
                mock_renderer_instance = MagicMock()
                mock_renderer_instance.render.return_value = ["/tmp/test.md"]
                mock_renderer_cls = MagicMock(return_value=mock_renderer_instance)
                with patch.dict(FORMAT_RENDERERS, {"hackerone_md": mock_renderer_cls}):
                    with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
                        with patch("workers.reporting_worker.pipeline.get_session") as mock_session:
                            mock_ctx2 = MagicMock()
                            mock_ctx2.__aenter__ = AsyncMock(return_value=mock_ctx2)
                            mock_ctx2.__aexit__ = AsyncMock(return_value=None)
                            mock_session.return_value = mock_ctx2
                            mock_ctx2.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
                            with patch("os.makedirs"):
                                with patch("shutil.move"):
                                    result = await pipeline.run(
                                        target_id=1,
                                        formats=["hackerone_md"],
                                        platform="hackerone",
                                        container_name="test",
                                        output_base="/tmp",
                                    )
                                    assert len(result) > 0
