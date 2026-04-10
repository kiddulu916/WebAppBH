"""Tests for LLM-powered report generation (5 platforms)."""
import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from workers.reporting_worker.models import (
    AffectedAsset,
    FindingGroup,
    ReportData,
    SummaryStats,
)

pytestmark = pytest.mark.anyio


def _make_report_data(platform: str = "hackerone") -> ReportData:
    """Build minimal ReportData for testing."""
    return ReportData(
        company_name="AcmeCorp",
        base_domain="acme.com",
        finding_groups=[
            FindingGroup(
                title="Reflected XSS in /search",
                severity="high",
                cvss_score=7.5,
                description="Input reflected without encoding",
                remediation="Encode all user input on output",
                source_tool="nuclei",
                affected_assets=[
                    AffectedAsset(
                        asset_value="acme.com",
                        port=443,
                        protocol="https",
                        poc='GET /search?q=<script>alert(1)</script>',
                    ),
                ],
            ),
        ],
        summary_stats=SummaryStats(critical=0, high=1, medium=0, low=0, info=0),
        generation_date="2026-04-10",
        platform=platform,
        formats=[f"llm_{platform}"],
    )


# ---------------------------------------------------------------------------
# Tests for build_report_prompt — all 5 platforms
# ---------------------------------------------------------------------------

class TestBuildReportPrompt:
    """Verify prompt builder includes key data for all 5 platforms."""

    @pytest.mark.parametrize("platform", [
        "hackerone", "bugcrowd", "intigriti", "yeswehack", "markdown",
    ])
    def test_prompt_contains_essential_fields(self, platform: str):
        from lib_webbh.prompts.report_writer import build_report_prompt
        data = _make_report_data(platform)
        prompt = build_report_prompt(data)

        assert "AcmeCorp" in prompt
        assert "acme.com" in prompt
        assert "Reflected XSS" in prompt
        assert "7.5" in prompt
        assert platform in prompt.lower()

    @pytest.mark.parametrize("platform", [
        "hackerone", "bugcrowd", "intigriti", "yeswehack", "markdown",
    ])
    def test_prompt_includes_poc(self, platform: str):
        from lib_webbh.prompts.report_writer import build_report_prompt
        data = _make_report_data(platform)
        prompt = build_report_prompt(data)

        assert "<script>alert(1)</script>" in prompt

    def test_prompt_includes_platform_guidance(self):
        from lib_webbh.prompts.report_writer import build_report_prompt, PLATFORM_GUIDANCE
        for platform in PLATFORM_GUIDANCE:
            data = _make_report_data(platform)
            prompt = build_report_prompt(data)
            assert PLATFORM_GUIDANCE[platform] in prompt

    def test_unknown_platform_falls_back_to_markdown(self):
        from lib_webbh.prompts.report_writer import build_report_prompt, PLATFORM_GUIDANCE
        data = _make_report_data("unknown_platform")
        prompt = build_report_prompt(data)
        assert PLATFORM_GUIDANCE["markdown"] in prompt


# ---------------------------------------------------------------------------
# Tests for LLMRenderer
# ---------------------------------------------------------------------------

class TestLLMRenderer:
    """Verify LLMRenderer calls LLMClient and writes output file."""

    async def test_render_writes_file(self, tmp_path):
        from workers.reporting_worker.renderers.llm_renderer import LLMRenderer

        mock_response = MagicMock()
        mock_response.text = "# XSS Report\n\nThis is a generated report."

        with patch("workers.reporting_worker.renderers.llm_renderer.LLMClient") as MockLLM:
            instance = MockLLM.return_value
            instance.generate = AsyncMock(return_value=mock_response)

            renderer = LLMRenderer()
            data = _make_report_data("hackerone")
            paths = await renderer.render(data, str(tmp_path))

            assert len(paths) == 1
            assert os.path.exists(paths[0])
            with open(paths[0]) as f:
                content = f.read()
            assert "XSS Report" in content

    async def test_render_calls_llm_with_system_prompt(self, tmp_path):
        from workers.reporting_worker.renderers.llm_renderer import LLMRenderer

        mock_response = MagicMock()
        mock_response.text = "report body"

        with patch("workers.reporting_worker.renderers.llm_renderer.LLMClient") as MockLLM:
            instance = MockLLM.return_value
            instance.generate = AsyncMock(return_value=mock_response)

            renderer = LLMRenderer()
            data = _make_report_data("bugcrowd")
            await renderer.render(data, str(tmp_path))

            call_kwargs = instance.generate.call_args.kwargs
            assert "system" in call_kwargs
            assert call_kwargs["system"]  # non-empty system prompt

    async def test_render_filename_contains_platform(self, tmp_path):
        from workers.reporting_worker.renderers.llm_renderer import LLMRenderer

        mock_response = MagicMock()
        mock_response.text = "report"

        with patch("workers.reporting_worker.renderers.llm_renderer.LLMClient") as MockLLM:
            instance = MockLLM.return_value
            instance.generate = AsyncMock(return_value=mock_response)

            renderer = LLMRenderer()
            data = _make_report_data("intigriti")
            paths = await renderer.render(data, str(tmp_path))

            assert "intigriti" in os.path.basename(paths[0])
            assert paths[0].endswith("_llm.md")


# ---------------------------------------------------------------------------
# Integration: all 5 LLM format keys exist in FORMAT_RENDERERS
# ---------------------------------------------------------------------------

class TestFormatRegistration:
    """Verify all 5 LLM format keys are registered in pipeline."""

    @pytest.mark.parametrize("fmt", [
        "llm_hackerone", "llm_bugcrowd", "llm_intigriti", "llm_yeswehack", "llm_markdown",
    ])
    def test_llm_format_registered(self, fmt: str):
        from workers.reporting_worker.pipeline import FORMAT_RENDERERS
        assert fmt in FORMAT_RENDERERS
