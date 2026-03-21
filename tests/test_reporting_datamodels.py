# tests/test_reporting_datamodels.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from workers.reporting_worker.models import (
    AffectedAsset,
    FindingGroup,
    ReportContext,
    ReportData,
    SummaryStats,
)


def test_summary_stats_total():
    stats = SummaryStats(critical=2, high=3, medium=5, low=1, info=0)
    assert stats.total_findings == 11


def test_finding_group_affected_count():
    group = FindingGroup(
        title="XSS", severity="high", cvss_score=7.5,
        description="Reflected XSS", remediation="Encode output",
        source_tool="nuclei",
        affected_assets=[
            AffectedAsset(asset_value="a.testcorp.com", port=443, protocol="https", service="http", poc="GET /vuln", screenshot_paths=[]),
            AffectedAsset(asset_value="b.testcorp.com", port=80, protocol="http", service="http", poc="GET /vuln2", screenshot_paths=[]),
        ],
    )
    assert len(group.affected_assets) == 2


def test_report_context_defaults():
    ctx = ReportContext(
        target_id=1, company_name="TestCorp", base_domain="testcorp.com",
        target_profile={}, vulnerabilities=[], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    assert ctx.target_id == 1
    assert ctx.screenshot_map == {}


def test_report_data_construction():
    stats = SummaryStats(critical=1, high=0, medium=0, low=0, info=0)
    data = ReportData(
        company_name="TestCorp", base_domain="testcorp.com",
        finding_groups=[], summary_stats=stats,
        generation_date="2026-03-21", platform="hackerone",
        formats=["hackerone_md"],
        assets=[], cloud_assets=[], api_schemas=[],
    )
    assert data.platform == "hackerone"
    assert data.summary_stats.total_findings == 1
