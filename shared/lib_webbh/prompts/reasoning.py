"""Prompt templates for LLM-powered vulnerability reasoning (10 analyses)."""
from __future__ import annotations

from lib_webbh.prompts.pentestgpt_adapted import REASONING_SYSTEM

REQUIRED_SCHEMA_INSTRUCTION = """\
Respond with valid JSON matching this schema:
{
  "insights": [
    {
      "vulnerability_id": <int>,
      "severity_assessment": "critical|high|medium|low|info",
      "exploitability": "<text>",
      "false_positive_likelihood": <float 0.0-1.0>,
      "chain_hypotheses": [{"with_vuln_id": <int>, "description": "<text>"}],
      "next_steps": "<text>",
      "bounty_estimate": {"low": <int>, "high": <int>, "currency": "USD"},
      "duplicate_likelihood": <float 0.0-1.0>,
      "owasp_cwe": {"owasp": "A01:2021", "cwe_id": 79, "cwe_name": "XSS"},
      "report_readiness_score": <float 0.0-1.0>,
      "report_readiness_notes": "<text>",
      "asset_criticality": "critical|high|medium|low",
      "asset_criticality_rationale": "<text>",
      "confidence": <float 0.0-1.0>
    }
  ]
}"""


def build_reasoning_prompt(
    target_info: dict,
    vulns_batch: list[dict],
) -> str:
    """Build the user prompt for a batch of vulnerabilities."""
    sections = [
        "# Vulnerability Analysis Request",
        "",
        f"**Target:** {target_info['domain']}",
        f"**Platform:** {target_info.get('platform', 'unknown')}",
        f"**Tech stack:** {', '.join(target_info.get('tech_stack', []))}",
        "",
        "## Vulnerabilities to Analyze",
        "",
    ]

    for vuln in vulns_batch:
        sections.append(f"### Vuln ID {vuln['id']}: {vuln['title']}")
        sections.append(f"- Severity: {vuln['severity']} (CVSS: {vuln.get('cvss_score', 'N/A')})")
        sections.append(f"- Source tool: {vuln.get('source_tool', 'unknown')}")
        sections.append(f"- Asset: {vuln.get('asset_value', 'N/A')}")
        if vuln.get("description"):
            sections.append(f"- Description: {vuln['description']}")
        if vuln.get("poc"):
            sections.append(f"- PoC: ```\n{vuln['poc']}\n```")
        if vuln.get("observations"):
            sections.append(f"- Observations: {', '.join(vuln['observations'])}")
        sections.append("")

    sections.append("## Required Output Format")
    sections.append("")
    sections.append(REQUIRED_SCHEMA_INSTRUCTION)

    return "\n".join(sections)


__all__ = ["REASONING_SYSTEM", "REQUIRED_SCHEMA_INSTRUCTION", "build_reasoning_prompt"]
