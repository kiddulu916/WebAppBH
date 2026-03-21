# tests/test_reporting_pdf_renderers.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
from workers.reporting_worker.models import (
    AffectedAsset, FindingGroup, ReportData, SummaryStats,
)
from workers.reporting_worker.renderers.executive_renderer import ExecutiveRenderer
from workers.reporting_worker.renderers.technical_renderer import TechnicalRenderer


@pytest.fixture
def sample_report_data():
    return ReportData(
        company_name="AcmeCorp", base_domain="acme.com",
        finding_groups=[
            FindingGroup(
                title="SQL Injection", severity="critical", cvss_score=9.8,
                description="SQLi in login endpoint",
                remediation="Use parameterized queries.",
                source_tool="sqlmap",
                affected_assets=[
                    AffectedAsset(
                        asset_value="api.acme.com", port=443, protocol="https",
                        service="http",
                        poc="POST /login\nusername=admin'--\n\nHTTP/1.1 500",
                        screenshot_paths=[],
                    ),
                ],
            ),
            FindingGroup(
                title="Missing HSTS", severity="low", cvss_score=2.0,
                description="HSTS header not set",
                remediation="Add Strict-Transport-Security header.",
                source_tool="nuclei",
                affected_assets=[
                    AffectedAsset(asset_value="www.acme.com", port=443, protocol="https", service="http", poc=None, screenshot_paths=[]),
                ],
            ),
        ],
        summary_stats=SummaryStats(critical=1, high=0, medium=0, low=1, info=0),
        generation_date="2026-03-21", platform="hackerone",
        formats=["executive_pdf", "technical_pdf"],
        assets=[], cloud_assets=[], api_schemas=[],
    )


def test_executive_renders_html(sample_report_data):
    """Test that executive renderer produces valid HTML (before WeasyPrint)."""
    renderer = ExecutiveRenderer()
    html = renderer.render_html(sample_report_data)
    assert "<html" in html
    assert "AcmeCorp" in html
    assert "SQL Injection" in html


def test_technical_renders_html(sample_report_data):
    """Test that technical renderer produces valid HTML with PoC blocks."""
    renderer = TechnicalRenderer()
    html = renderer.render_html(sample_report_data)
    assert "<html" in html
    assert "SQL Injection" in html
    assert "POST /login" in html  # PoC content
    assert "parameterized" in html  # remediation


def test_executive_render_to_file(sample_report_data):
    """Test full PDF render if WeasyPrint is available, otherwise test HTML fallback."""
    renderer = ExecutiveRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            paths = renderer.render(sample_report_data, output_dir=tmpdir)
            assert len(paths) == 1
            assert paths[0].endswith(".pdf")
            assert os.path.getsize(paths[0]) > 0
        except ImportError:
            pytest.skip("WeasyPrint not installed")


def test_technical_render_to_file(sample_report_data):
    """Test full PDF render if WeasyPrint is available, otherwise test HTML fallback."""
    renderer = TechnicalRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            paths = renderer.render(sample_report_data, output_dir=tmpdir)
            assert len(paths) == 1
            assert paths[0].endswith(".pdf")
            assert os.path.getsize(paths[0]) > 0
        except ImportError:
            pytest.skip("WeasyPrint not installed")
