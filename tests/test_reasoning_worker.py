"""Tests for the LLM-powered vulnerability reasoning engine (10 analyses)."""
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_vuln_batch():
    """Minimal vuln batch data for prompt building."""
    return [
        {
            "id": 1,
            "title": "Reflected XSS in /search",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "Input reflected without encoding",
            "poc": "GET /search?q=<script>alert(1)</script>",
            "source_tool": "nuclei",
            "asset_value": "acme.com",
            "observations": ["Apache/2.4", "PHP/8.1"],
        },
        {
            "id": 2,
            "title": "SQL Injection in /login",
            "severity": "critical",
            "cvss_score": 9.8,
            "description": "Union-based SQLi in username param",
            "poc": "POST /login username=' UNION SELECT 1--",
            "source_tool": "sqlmap",
            "asset_value": "acme.com",
            "observations": ["MySQL 8.0"],
        },
    ]


def _sample_target_info():
    return {
        "target_id": 42,
        "domain": "acme.com",
        "tech_stack": ["Apache/2.4", "PHP/8.1", "MySQL 8.0"],
        "platform": "hackerone",
    }


def _sample_llm_response():
    """A valid JSON response matching the expected schema."""
    return {
        "insights": [
            {
                "vulnerability_id": 1,
                "severity_assessment": "high",
                "exploitability": "Easily exploitable via URL manipulation",
                "false_positive_likelihood": 0.1,
                "chain_hypotheses": [{"with_vuln_id": 2, "description": "XSS + SQLi for session theft"}],
                "next_steps": "Test with different encoding bypasses",
                "bounty_estimate": {"low": 500, "high": 2000, "currency": "USD"},
                "duplicate_likelihood": 0.3,
                "owasp_cwe": {"owasp": "A03:2021", "cwe_id": 79, "cwe_name": "Cross-site Scripting"},
                "report_readiness_score": 0.8,
                "report_readiness_notes": "Good PoC, needs impact section",
                "asset_criticality": "high",
                "asset_criticality_rationale": "Main search endpoint, user-facing",
                "confidence": 0.85,
            },
            {
                "vulnerability_id": 2,
                "severity_assessment": "critical",
                "exploitability": "Trivially exploitable, dumps all tables",
                "false_positive_likelihood": 0.05,
                "chain_hypotheses": [],
                "next_steps": "Enumerate all tables, extract password hashes",
                "bounty_estimate": {"low": 3000, "high": 10000, "currency": "USD"},
                "duplicate_likelihood": 0.2,
                "owasp_cwe": {"owasp": "A03:2021", "cwe_id": 89, "cwe_name": "SQL Injection"},
                "report_readiness_score": 0.9,
                "report_readiness_notes": "Comprehensive PoC with sqlmap output",
                "asset_criticality": "critical",
                "asset_criticality_rationale": "Login endpoint, controls authentication",
                "confidence": 0.95,
            },
        ]
    }


# ---------------------------------------------------------------------------
# Tests for prompt builder
# ---------------------------------------------------------------------------

class TestBuildReasoningPrompt:
    def test_prompt_contains_vuln_details(self):
        from lib_webbh.prompts.reasoning import build_reasoning_prompt
        prompt = build_reasoning_prompt(_sample_target_info(), _sample_vuln_batch())

        assert "Reflected XSS" in prompt
        assert "SQL Injection" in prompt
        assert "7.5" in prompt
        assert "9.8" in prompt
        assert "nuclei" in prompt
        assert "sqlmap" in prompt

    def test_prompt_contains_target_info(self):
        from lib_webbh.prompts.reasoning import build_reasoning_prompt
        prompt = build_reasoning_prompt(_sample_target_info(), _sample_vuln_batch())

        assert "acme.com" in prompt
        assert "hackerone" in prompt

    def test_prompt_contains_tech_stack(self):
        from lib_webbh.prompts.reasoning import build_reasoning_prompt
        prompt = build_reasoning_prompt(_sample_target_info(), _sample_vuln_batch())

        assert "Apache/2.4" in prompt
        assert "PHP/8.1" in prompt

    def test_prompt_contains_json_schema_instruction(self):
        from lib_webbh.prompts.reasoning import build_reasoning_prompt, REQUIRED_SCHEMA_INSTRUCTION
        prompt = build_reasoning_prompt(_sample_target_info(), _sample_vuln_batch())

        assert "vulnerability_id" in prompt
        assert "severity_assessment" in prompt
        assert "false_positive_likelihood" in prompt
        assert "bounty_estimate" in prompt
        assert "duplicate_likelihood" in prompt
        assert "owasp_cwe" in prompt
        assert "report_readiness_score" in prompt
        assert "asset_criticality" in prompt

    def test_prompt_includes_poc(self):
        from lib_webbh.prompts.reasoning import build_reasoning_prompt
        prompt = build_reasoning_prompt(_sample_target_info(), _sample_vuln_batch())

        assert "<script>alert(1)</script>" in prompt
        assert "UNION SELECT" in prompt


# ---------------------------------------------------------------------------
# Tests for response parser
# ---------------------------------------------------------------------------

class TestParseResponse:
    def test_parse_valid_response(self):
        from workers.reasoning_worker.analyzer import parse_llm_response
        raw = json.dumps(_sample_llm_response())
        insights = parse_llm_response(raw)

        assert len(insights) == 2
        assert insights[0]["vulnerability_id"] == 1
        assert insights[1]["vulnerability_id"] == 2
        assert insights[0]["severity_assessment"] == "high"
        assert insights[1]["false_positive_likelihood"] == 0.05

    def test_parse_includes_all_10_fields(self):
        from workers.reasoning_worker.analyzer import parse_llm_response
        raw = json.dumps(_sample_llm_response())
        insights = parse_llm_response(raw)

        required_fields = [
            "vulnerability_id", "severity_assessment", "exploitability",
            "false_positive_likelihood", "chain_hypotheses", "next_steps",
            "bounty_estimate", "duplicate_likelihood", "owasp_cwe",
            "report_readiness_score", "report_readiness_notes",
            "asset_criticality", "asset_criticality_rationale", "confidence",
        ]
        for insight in insights:
            for field in required_fields:
                assert field in insight, f"Missing field: {field}"

    def test_parse_handles_malformed_json(self):
        from workers.reasoning_worker.analyzer import parse_llm_response
        result = parse_llm_response("not valid json {{{")
        assert result == []

    def test_parse_handles_missing_insights_key(self):
        from workers.reasoning_worker.analyzer import parse_llm_response
        result = parse_llm_response(json.dumps({"data": []}))
        assert result == []


# ---------------------------------------------------------------------------
# Tests for VulnerabilityInsight DB model
# ---------------------------------------------------------------------------

class TestVulnerabilityInsightModel:
    def test_model_exists_and_has_table(self):
        from lib_webbh.database import VulnerabilityInsight
        assert VulnerabilityInsight.__tablename__ == "vulnerability_insights"

    def test_model_has_all_10_analysis_fields(self):
        from lib_webbh.database import VulnerabilityInsight
        expected_columns = [
            "severity_assessment", "exploitability", "false_positive_likelihood",
            "chain_hypotheses", "next_steps", "bounty_estimate",
            "duplicate_likelihood", "owasp_cwe", "report_readiness_score",
            "report_readiness_notes", "asset_criticality", "asset_criticality_rationale",
        ]
        table_columns = {c.name for c in VulnerabilityInsight.__table__.columns}
        for col in expected_columns:
            assert col in table_columns, f"Missing column: {col}"

    def test_model_has_metadata_fields(self):
        from lib_webbh.database import VulnerabilityInsight
        table_columns = {c.name for c in VulnerabilityInsight.__table__.columns}
        assert "confidence" in table_columns
        assert "raw_analysis" in table_columns
        assert "target_id" in table_columns
        assert "vulnerability_id" in table_columns


# ---------------------------------------------------------------------------
# Tests for chunking utility
# ---------------------------------------------------------------------------

class TestChunkVulns:
    def test_chunk_exact_batch(self):
        from workers.reasoning_worker.analyzer import chunk_vulns
        vulns = list(range(10))
        chunks = list(chunk_vulns(vulns, batch_size=10))
        assert len(chunks) == 1
        assert chunks[0] == vulns

    def test_chunk_multiple_batches(self):
        from workers.reasoning_worker.analyzer import chunk_vulns
        vulns = list(range(25))
        chunks = list(chunk_vulns(vulns, batch_size=10))
        assert len(chunks) == 3
        assert len(chunks[0]) == 10
        assert len(chunks[1]) == 10
        assert len(chunks[2]) == 5

    def test_chunk_empty(self):
        from workers.reasoning_worker.analyzer import chunk_vulns
        assert list(chunk_vulns([], batch_size=10)) == []
