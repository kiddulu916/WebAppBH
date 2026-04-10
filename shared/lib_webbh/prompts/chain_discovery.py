"""Prompt templates for LLM-powered exploit chain discovery (Task 5)."""

from __future__ import annotations

from lib_webbh.prompts.pentestgpt_adapted import CHAIN_DISCOVERY_SYSTEM

CHAIN_JSON_SCHEMA = """\
Respond with valid JSON matching this schema:
{
  "chains": [
    {
      "vuln_ids": [<int>, ...],
      "steps": ["<step description>", ...],
      "goal": "<what the attacker gains — e.g., account takeover, data exfiltration, RCE>",
      "confidence": <float 0.0-1.0>,
      "expected_impact": "<impact description>"
    }
  ]
}

Rules:
- Each chain must use 2-4 steps (no more, no fewer).
- Each chain must include a non-empty "goal" string.
- Rate your confidence 0.0-1.0 for each chain.
- Only reference vulnerability IDs explicitly listed below.
- Do NOT invent vulnerabilities that are not in the provided list.
"""


def build_chain_prompt(
    findings: list[dict],
    existing_chains: list[tuple],
) -> str:
    """Build the user prompt for the chain discovery LLM call.

    Parameters
    ----------
    findings
        List of finding dicts, each with at least ``id``, ``title``,
        ``severity``, ``evidence_confidence``, ``description``.
    existing_chains
        Template chain results from ``ChainEvaluator``, as
        ``(chain_name, EvaluationResult)`` tuples.
    """
    sections = [
        "# Exploit Chain Discovery Request",
        "",
        "## Available Findings",
        "",
    ]

    for f in findings:
        sections.append(
            f"- **ID {f['id']}**: {f['title']} "
            f"(severity={f.get('severity', 'unknown')}, "
            f"confidence={f.get('evidence_confidence', 'N/A')})"
        )
        if f.get("description"):
            sections.append(f"  Description: {f['description']}")
        sections.append("")

    sections.append("## Existing Template Chain Results")
    sections.append("")
    if existing_chains:
        for name, result in existing_chains:
            sections.append(f"- **{name}**: viability={result.viability.value}")
    else:
        sections.append("- (none)")
    sections.append("")

    sections.append("## Instructions")
    sections.append("")
    sections.append(
        "Propose novel exploit chains that combine vulnerabilities from the list above "
        "for greater impact than any single finding. Avoid chains that duplicate the "
        "existing template results above."
    )
    sections.append("")
    sections.append(CHAIN_JSON_SCHEMA)

    return "\n".join(sections)


__all__ = [
    "CHAIN_DISCOVERY_SYSTEM",
    "build_chain_prompt",
    "CHAIN_JSON_SCHEMA",
]
