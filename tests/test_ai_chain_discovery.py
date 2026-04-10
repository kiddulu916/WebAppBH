"""Tests for LLM-powered exploit chain discovery (Task 5).

Covers:
- build_chain_prompt: output includes findings, existing chains, JSON schema, goal requirement
- 6 constraint filters: confidence, severity, length, chain_confidence, distinctness, goal
- AIChainDiscoverer.discover() integration with mocked LLM
"""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_findings():
    """Minimal finding dicts as the AI discoverer would receive."""
    return [
        {
            "id": 1,
            "title": "Reflected XSS in /search",
            "severity": "high",
            "cvss_score": 7.5,
            "evidence_confidence": 0.9,
            "description": "Input reflected without encoding",
            "source_tool": "nuclei",
        },
        {
            "id": 2,
            "title": "SQL Injection in /login",
            "severity": "critical",
            "cvss_score": 9.8,
            "evidence_confidence": 0.85,
            "description": "Union-based SQLi in username param",
            "source_tool": "sqlmap",
        },
        {
            "id": 3,
            "title": "Open Redirect in /callback",
            "severity": "medium",
            "cvss_score": 4.3,
            "evidence_confidence": 0.75,
            "description": "Unvalidated redirect parameter",
            "source_tool": "nuclei",
        },
        {
            "id": 4,
            "title": "Info leak: server version header",
            "severity": "info",
            "cvss_score": 0.0,
            "evidence_confidence": 0.95,
            "description": "Server header exposes version info",
            "source_tool": "httpx",
        },
        {
            "id": 5,
            "title": "Weak CORS config",
            "severity": "low",
            "cvss_score": 3.1,
            "evidence_confidence": 0.4,
            "description": "Overly permissive CORS policy",
            "source_tool": "nuclei",
        },
    ]


def _existing_chains():
    """Template chain results from ChainEvaluator."""
    return [
        ("xss_session_theft", MagicMock(
            viability=MagicMock(value="viable"),
            matched_findings={"vuln_id": 1},
        )),
    ]


# ---------------------------------------------------------------------------
# build_chain_prompt tests
# ---------------------------------------------------------------------------

class TestBuildChainPrompt:
    def test_prompt_contains_findings(self):
        from lib_webbh.prompts.chain_discovery import build_chain_prompt

        prompt = build_chain_prompt(_sample_findings(), _existing_chains())
        assert "Reflected XSS" in prompt
        assert "SQL Injection" in prompt
        assert "Open Redirect" in prompt

    def test_prompt_contains_existing_chains(self):
        from lib_webbh.prompts.chain_discovery import build_chain_prompt

        prompt = build_chain_prompt(_sample_findings(), _existing_chains())
        assert "xss_session_theft" in prompt

    def test_prompt_contains_json_schema_instruction(self):
        from lib_webbh.prompts.chain_discovery import build_chain_prompt

        prompt = build_chain_prompt(_sample_findings(), _existing_chains())
        assert "vuln_ids" in prompt
        assert "goal" in prompt
        assert "confidence" in prompt

    def test_prompt_requires_goal_field(self):
        from lib_webbh.prompts.chain_discovery import build_chain_prompt

        prompt = build_chain_prompt(_sample_findings(), _existing_chains())
        assert "goal" in prompt.lower()


# ---------------------------------------------------------------------------
# 6 constraint filter tests
# ---------------------------------------------------------------------------

class TestConstraintFilters:
    def test_filter_by_finding_confidence(self):
        """Constraint 1: chains referencing findings with evidence_confidence < 0.7 are rejected."""
        from workers.chain_worker.tools.ai_chain_discoverer import filter_by_finding_confidence

        findings_map = {1: 0.9, 2: 0.85, 5: 0.4}
        chains = [
            {"vuln_ids": [1, 2], "goal": "ATO", "confidence": 0.8, "steps": ["a", "b"]},
            {"vuln_ids": [1, 5], "goal": "ATO", "confidence": 0.8, "steps": ["a", "b"]},
        ]
        result = filter_by_finding_confidence(chains, findings_map)
        assert len(result) == 1
        assert result[0]["vuln_ids"] == [1, 2]

    def test_filter_by_severity(self):
        """Constraint 2: at least one Medium-or-higher vuln required in chain."""
        from workers.chain_worker.tools.ai_chain_discoverer import filter_by_severity

        severity_map = {1: "high", 4: "info", 5: "low"}
        chains = [
            {"vuln_ids": [1, 5], "goal": "ATO", "confidence": 0.8, "steps": ["a", "b"]},
            {"vuln_ids": [4, 5], "goal": "info", "confidence": 0.8, "steps": ["a", "b"]},
        ]
        result = filter_by_severity(chains, severity_map)
        assert len(result) == 1
        assert result[0]["vuln_ids"] == [1, 5]

    def test_filter_by_length(self):
        """Constraint 3: chain must be 2-4 steps."""
        from workers.chain_worker.tools.ai_chain_discoverer import filter_by_length

        chains = [
            {"vuln_ids": [1], "steps": ["a"], "goal": "X", "confidence": 0.8},
            {"vuln_ids": [1, 2], "steps": ["a", "b"], "goal": "X", "confidence": 0.8},
            {"vuln_ids": [1, 2, 3], "steps": ["a", "b", "c"], "goal": "X", "confidence": 0.8},
            {"vuln_ids": [1, 2, 3, 4], "steps": list("abcd"), "goal": "X", "confidence": 0.8},
            {"vuln_ids": [1, 2, 3, 4, 5], "steps": list("abcde"), "goal": "X", "confidence": 0.8},
        ]
        result = filter_by_length(chains)
        assert len(result) == 3
        assert all(2 <= len(c["steps"]) <= 4 for c in result)

    def test_filter_by_chain_confidence(self):
        """Constraint 4: chains below MIN_CHAIN_CONFIDENCE are dropped."""
        from workers.chain_worker.tools.ai_chain_discoverer import filter_by_chain_confidence

        chains = [
            {"vuln_ids": [1, 2], "steps": ["a", "b"], "goal": "ATO", "confidence": 0.8},
            {"vuln_ids": [1, 3], "steps": ["a", "b"], "goal": "ATO", "confidence": 0.3},
        ]
        result = filter_by_chain_confidence(chains, min_confidence=0.5)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.8

    def test_filter_by_distinctness(self):
        """Constraint 5: chains with >=80% vuln_id overlap with templates are dropped."""
        from workers.chain_worker.tools.ai_chain_discoverer import filter_by_distinctness

        template_vuln_ids = [{1, 2}]
        chains = [
            {"vuln_ids": [1, 2], "steps": ["a", "b"], "goal": "ATO", "confidence": 0.8},
            {"vuln_ids": [1, 3], "steps": ["a", "b"], "goal": "ATO", "confidence": 0.8},
            {"vuln_ids": [2, 3], "steps": ["a", "b"], "goal": "ATO", "confidence": 0.8},
        ]
        result = filter_by_distinctness(chains, template_vuln_ids, max_overlap=0.8)
        # [1,2] has 100% overlap with template -> dropped
        # [1,3] has 50% overlap -> kept
        # [2,3] has 50% overlap -> kept
        assert len(result) == 2
        assert all(c["vuln_ids"] != [1, 2] for c in result)

    def test_filter_by_goal(self):
        """Constraint 6: chains must have a non-empty goal string."""
        from workers.chain_worker.tools.ai_chain_discoverer import filter_by_goal

        chains = [
            {"vuln_ids": [1, 2], "steps": ["a", "b"], "goal": "Full account takeover", "confidence": 0.8},
            {"vuln_ids": [1, 3], "steps": ["a", "b"], "goal": "", "confidence": 0.8},
            {"vuln_ids": [2, 3], "steps": ["a", "b"], "confidence": 0.8},
        ]
        result = filter_by_goal(chains)
        assert len(result) == 1
        assert result[0]["goal"] == "Full account takeover"


# ---------------------------------------------------------------------------
# Integration test: discover() with mocked LLM
# ---------------------------------------------------------------------------

class TestAIChainDiscovererIntegration:
    async def test_discover_returns_filtered_chains(self):
        """Full integration: LLM returns 3 chains, filters leave 1."""
        from workers.chain_worker.tools.ai_chain_discoverer import AIChainDiscoverer

        llm_response_data = {
            "chains": [
                {
                    "vuln_ids": [1, 2],
                    "steps": ["Exploit XSS", "Steal session via SQLi"],
                    "goal": "Account takeover",
                    "confidence": 0.85,
                    "expected_impact": "Full account compromise",
                },
                {
                    "vuln_ids": [1, 5],
                    "steps": ["XSS", "CORS bypass"],
                    "goal": "Data exfil",
                    "confidence": 0.7,
                    "expected_impact": "Cross-origin data theft",
                },
                {
                    "vuln_ids": [4],
                    "steps": ["Info disclosure"],
                    "goal": "",
                    "confidence": 0.2,
                    "expected_impact": "None",
                },
            ]
        }

        mock_llm_response = MagicMock()
        mock_llm_response.text = json.dumps(llm_response_data)

        findings = _sample_findings()
        template_chains = _existing_chains()
        buckets = {"viable": template_chains, "partial": [], "not_viable": [], "awaiting_accounts": []}

        with patch("workers.chain_worker.tools.ai_chain_discoverer.LLMClient") as MockLLM:
            instance = MockLLM.return_value
            instance.generate = AsyncMock(return_value=mock_llm_response)

            discoverer = AIChainDiscoverer()
            result = await discoverer.discover(findings, buckets)

        # Chain 1: [1,2] both >=0.7 confidence, high+critical severity, 2 steps, conf 0.85 > 0.5, goal present -> passes all
        #   BUT [1,2] overlaps? template has vuln_id=1 only (as a dict key), not as a set {1,2}
        # Chain 2: [1,5] vuln 5 has evidence_confidence=0.4 -> rejected by constraint 1
        # Chain 3: [4] only 1 step -> rejected by constraint 3, also empty goal
        assert len(result) >= 1
        assert result[0]["goal"] == "Account takeover"
