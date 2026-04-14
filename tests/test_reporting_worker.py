# tests/test_reporting_worker.py
"""Tests for reporting_worker pipeline, models, and deduplicator."""

import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.reporting_worker.models import (
    AffectedAsset,
    FindingGroup,
    ReportContext,
    ReportData,
    SummaryStats,
    sanitize_filename,
)
from workers.reporting_worker.pipeline import STAGES, STAGE_INDEX, FORMAT_RENDERERS, Pipeline
from workers.reporting_worker.deduplicator import deduplicate_and_enrich, SEVERITY_CVSS


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


def test_sanitize_filename():
    assert sanitize_filename("hello world!@#") == "hello_world___"
    assert sanitize_filename("report-2024.pdf") == "report-2024.pdf"
    assert sanitize_filename("a/b\\c") == "a_b_c"


def test_summary_stats_total():
    stats = SummaryStats(critical=1, high=2, medium=3, low=4, info=5)
    assert stats.total_findings == 15


def test_summary_stats_defaults():
    stats = SummaryStats()
    assert stats.total_findings == 0


def test_finding_group_fields():
    fg = FindingGroup(
        title="XSS", severity="high", cvss_score=7.5,
        description="Cross-site scripting", remediation="Encode output",
        source_tool="dalfox",
    )
    assert fg.title == "XSS"
    assert fg.cvss_score == 7.5
    assert fg.affected_assets == []


def test_affected_asset_defaults():
    a = AffectedAsset(asset_value="example.com")
    assert a.port is None
    assert a.screenshot_paths == []


def test_report_context_fields():
    ctx = ReportContext(
        target_id=1, company_name="Acme", base_domain="acme.com",
        target_profile={}, vulnerabilities=[], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[],
    )
    assert ctx.company_name == "Acme"
    assert ctx.screenshot_map == {}


def test_report_data_fields():
    rd = ReportData(
        company_name="Acme", base_domain="acme.com",
        finding_groups=[], summary_stats=SummaryStats(),
        generation_date="2026-01-01", platform="hackerone", formats=["hackerone_md"],
    )
    assert rd.platform == "hackerone"
    assert rd.assets == []


# ---------------------------------------------------------------------------
# Pipeline constants
# ---------------------------------------------------------------------------


def test_pipeline_stage_count():
    assert len(STAGES) == 4


def test_pipeline_stage_names():
    assert STAGES[0].name == "data_gathering"
    assert STAGES[1].name == "deduplication"
    assert STAGES[2].name == "rendering"
    assert STAGES[3].name == "export"


def test_stage_index():
    assert STAGE_INDEX["data_gathering"] == 0
    assert STAGE_INDEX["export"] == 3


def test_format_renderers_keys():
    assert "hackerone_md" in FORMAT_RENDERERS
    assert "executive_pdf" in FORMAT_RENDERERS
    assert "llm_hackerone" in FORMAT_RENDERERS


# ---------------------------------------------------------------------------
# Deduplicator tests
# ---------------------------------------------------------------------------


def _make_vuln(title="XSS", severity="high", source_tool="dalfox",
               cvss=None, remediation=None, poc=None, asset=None):
    v = MagicMock()
    v.title = title
    v.severity = severity
    v.source_tool = source_tool
    v.cvss_score = cvss
    v.remediation = remediation
    v.poc = poc
    v.asset = asset
    v.asset_id = asset.id if asset else None
    return v


def test_dedup_empty():
    ctx = ReportContext(
        target_id=1, company_name="Acme", base_domain="acme.com",
        target_profile={}, vulnerabilities=[], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[],
    )
    rd = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert rd.company_name == "Acme"
    assert len(rd.finding_groups) == 0
    assert rd.summary_stats.total_findings == 0


def test_dedup_groups_by_key():
    v1 = _make_vuln(title="XSS", severity="high", source_tool="dalfox")
    v2 = _make_vuln(title="XSS", severity="high", source_tool="dalfox")
    v3 = _make_vuln(title="SQLi", severity="critical", source_tool="sqlmap")

    ctx = ReportContext(
        target_id=1, company_name="Corp", base_domain="corp.com",
        target_profile={}, vulnerabilities=[v1, v2, v3], assets=[],
        locations=[], observations=[], cloud_assets=[], api_schemas=[],
    )
    rd = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert len(rd.finding_groups) == 2
    # Sorted by CVSS descending - critical (9.5) before high (7.5)
    assert rd.finding_groups[0].title == "SQLi"
    assert rd.finding_groups[1].title == "XSS"
    assert rd.summary_stats.critical == 1
    assert rd.summary_stats.high == 1


def test_dedup_uses_cvss_from_vuln():
    v = _make_vuln(title="Custom", severity="medium", cvss=8.1)
    ctx = ReportContext(
        target_id=1, company_name="X", base_domain="x.com",
        target_profile={}, vulnerabilities=[v], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[],
    )
    rd = deduplicate_and_enrich(ctx, platform="hackerone", formats=[])
    assert rd.finding_groups[0].cvss_score == 8.1


def test_severity_cvss_mapping():
    assert SEVERITY_CVSS["critical"] == 9.5
    assert SEVERITY_CVSS["info"] == 0.0


# ---------------------------------------------------------------------------
# Pipeline run (mocked)
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_pipeline_run_all_stages():
    """Pipeline runs all 4 stages when starting fresh."""
    ctx = ReportContext(
        target_id=1, company_name="TestCo", base_domain="test.com",
        target_profile={}, vulnerabilities=[], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[],
    )
    rd = ReportData(
        company_name="TestCo", base_domain="test.com",
        finding_groups=[], summary_stats=SummaryStats(),
        generation_date="2026-01-01", platform="hackerone", formats=["hackerone_md"],
    )

    pipeline = Pipeline()

    with patch.object(pipeline, "_get_resume_index", new_callable=AsyncMock, return_value=0), \
         patch.object(pipeline, "_update_phase", new_callable=AsyncMock) as mock_phase, \
         patch.object(pipeline, "_mark_completed", new_callable=AsyncMock) as mock_complete, \
         patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock), \
         patch("workers.reporting_worker.pipeline.gather_report_data", new_callable=AsyncMock, return_value=ctx), \
         patch("workers.reporting_worker.pipeline.deduplicate_and_enrich", return_value=rd), \
         patch("os.makedirs"), \
         patch("shutil.rmtree"):
        result = await pipeline.run(
            target_id=1, formats=[],
            platform="hackerone", container_name="reporting-test",
        )

    assert isinstance(result, list)
    assert mock_phase.call_count == 4  # 4 stages
    mock_complete.assert_called_once()


@pytest.mark.anyio
async def test_pipeline_resume_from_rendering():
    """Pipeline skips already-completed stages when resuming."""
    ctx = ReportContext(
        target_id=1, company_name="TestCo", base_domain="test.com",
        target_profile={}, vulnerabilities=[], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[],
    )
    rd = ReportData(
        company_name="TestCo", base_domain="test.com",
        finding_groups=[], summary_stats=SummaryStats(),
        generation_date="2026-01-01", platform="hackerone", formats=["hackerone_md"],
    )

    pipeline = Pipeline()

    # Resume from after deduplication (index 2 = rendering)
    with patch.object(pipeline, "_get_resume_index", new_callable=AsyncMock, return_value=2), \
         patch.object(pipeline, "_update_phase", new_callable=AsyncMock) as mock_phase, \
         patch.object(pipeline, "_mark_completed", new_callable=AsyncMock), \
         patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock), \
         patch("workers.reporting_worker.pipeline.gather_report_data", new_callable=AsyncMock, return_value=ctx), \
         patch("workers.reporting_worker.pipeline.deduplicate_and_enrich", return_value=rd), \
         patch("os.makedirs"), \
         patch("shutil.rmtree"):
        await pipeline.run(
            target_id=1, formats=[],
            platform="hackerone", container_name="reporting-test",
        )

    # Only rendering + export phases updated (skipped data_gathering + deduplication)
    assert mock_phase.call_count == 2
