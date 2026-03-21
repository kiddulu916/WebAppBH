# tests/test_reporting_deduplicator.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from unittest.mock import MagicMock
from workers.reporting_worker.deduplicator import deduplicate_and_enrich
from workers.reporting_worker.models import ReportContext


def _make_vuln(title, severity, source_tool, asset_value=None, poc=None, asset_id=None, cvss_score=None, remediation=None):
    v = MagicMock()
    v.title = title
    v.severity = severity
    v.source_tool = source_tool
    v.poc = poc
    v.cvss_score = cvss_score
    v.remediation = remediation
    v.description = f"Description of {title}"
    v.asset_id = asset_id
    if asset_value:
        v.asset = MagicMock()
        v.asset.asset_value = asset_value
        v.asset.locations = [MagicMock(port=443, protocol="https", service="http")]
    else:
        v.asset = None
    return v


def test_groups_by_source_title_severity():
    vulns = [
        _make_vuln("XSS", "high", "nuclei", "a.com", asset_id=1),
        _make_vuln("XSS", "high", "nuclei", "b.com", asset_id=2),
        _make_vuln("XSS", "medium", "nuclei", "c.com", asset_id=3),
    ]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    # "XSS/high/nuclei" and "XSS/medium/nuclei" = 2 groups
    assert len(data.finding_groups) == 2


def test_cvss_fallback_when_null():
    vulns = [_make_vuln("SQLi", "critical", "sqlmap", "d.com", asset_id=1)]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert data.finding_groups[0].cvss_score == 9.5  # critical midpoint


def test_cvss_uses_column_when_present():
    vulns = [_make_vuln("SQLi", "critical", "sqlmap", "d.com", asset_id=1, cvss_score=9.8)]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert data.finding_groups[0].cvss_score == 9.8


def test_sorted_by_cvss_descending():
    vulns = [
        _make_vuln("Info Leak", "low", "nuclei", "a.com", asset_id=1),
        _make_vuln("RCE", "critical", "nuclei", "b.com", asset_id=2),
        _make_vuln("XSS", "high", "nuclei", "c.com", asset_id=3),
    ]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    scores = [g.cvss_score for g in data.finding_groups]
    assert scores == sorted(scores, reverse=True)


def test_summary_stats_counts():
    vulns = [
        _make_vuln("A", "critical", "t", "a.com", asset_id=1),
        _make_vuln("B", "high", "t", "b.com", asset_id=2),
        _make_vuln("C", "high", "t", "c.com", asset_id=3),
        _make_vuln("D", "medium", "t", "d.com", asset_id=4),
    ]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert data.summary_stats.critical == 1
    assert data.summary_stats.high == 2
    assert data.summary_stats.medium == 1
    assert data.summary_stats.total_findings == 4
