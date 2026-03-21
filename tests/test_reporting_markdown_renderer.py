# tests/test_reporting_markdown_renderer.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
from workers.reporting_worker.models import (
    AffectedAsset, FindingGroup, ReportData, SummaryStats,
)
from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer


@pytest.fixture
def sample_report_data():
    return ReportData(
        company_name="AcmeCorp", base_domain="acme.com",
        finding_groups=[
            FindingGroup(
                title="Reflected XSS", severity="high", cvss_score=7.5,
                description="XSS in search parameter",
                remediation="Encode all output.",
                source_tool="nuclei",
                affected_assets=[
                    AffectedAsset(
                        asset_value="app.acme.com", port=443, protocol="https",
                        service="http",
                        poc="GET /search?q=<script>alert(1)</script>\nHTTP/1.1 200 OK\n...",
                        screenshot_paths=[],
                    ),
                ],
            ),
        ],
        summary_stats=SummaryStats(critical=0, high=1, medium=0, low=0, info=0),
        generation_date="2026-03-21", platform="hackerone",
        formats=["hackerone_md"], assets=[], cloud_assets=[], api_schemas=[],
    )


def test_markdown_renderer_produces_files(sample_report_data):
    renderer = MarkdownRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = renderer.render(sample_report_data, output_dir=tmpdir)
        assert len(paths) >= 1
        for p in paths:
            assert os.path.exists(p)
            assert p.endswith(".md")


def test_hackerone_template_has_required_sections(sample_report_data):
    renderer = MarkdownRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = renderer.render(sample_report_data, output_dir=tmpdir)
        content = open(paths[0]).read()
        assert "Reflected XSS" in content
        assert "high" in content.lower() or "7.5" in content


def test_bugcrowd_template(sample_report_data):
    sample_report_data.platform = "bugcrowd"
    renderer = MarkdownRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = renderer.render(sample_report_data, output_dir=tmpdir)
        assert len(paths) >= 1
        content = open(paths[0]).read()
        assert "Reflected XSS" in content
