"""Prompt templates for LLM-powered report generation (5 platforms)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from lib_webbh.prompts.pentestgpt_adapted import REPORT_WRITER_SYSTEM as SYSTEM_PROMPT

if TYPE_CHECKING:
    from workers.reporting_worker.models import ReportData


PLATFORM_GUIDANCE = {
    "hackerone": (
        "Format for HackerOne: use ## headers, include a Summary, "
        "## Steps to Reproduce (numbered), ## Impact section, "
        "and ## Remediation. Reference CVSS score."
    ),
    "bugcrowd": (
        "Format for Bugcrowd: use clear headers, include Overview, "
        "Proof of Concept (with request/response), Impact, and Fix Recommendation. "
        "Use Bugcrowd VRT category names when possible."
    ),
    "intigriti": (
        "Format for Intigriti: include a Description, Proof of Concept, "
        "Steps to Reproduce, Impact, and Recommendation. Reference the "
        "Intigriti taxonomy category (e.g., 'Cross-site Scripting (Reflected)')."
    ),
    "yeswehack": (
        "Format for YesWeHack: include Summary, Vulnerability Type, "
        "Detailed Description, Reproduction Steps, Impact Analysis, and Fix. "
        "Include the CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/...)."
    ),
    "markdown": (
        "Format as clean generic markdown: # Title, ## Summary, ## Steps to Reproduce, "
        "## Impact, ## Remediation. No platform-specific tags."
    ),
}


def build_report_prompt(data: "ReportData") -> str:
    """Build the user prompt from ReportData for the LLM."""
    platform = (data.platform or "hackerone").lower()
    guidance = PLATFORM_GUIDANCE.get(platform, PLATFORM_GUIDANCE["markdown"])

    sections = [
        "# Report Generation Request",
        "",
        f"**Target:** {data.company_name} ({data.base_domain})",
        f"**Platform:** {platform}",
        f"**Date:** {data.generation_date}",
        "",
        "## Platform Formatting",
        guidance,
        "",
        "## Summary Statistics",
        f"Critical: {data.summary_stats.critical} | High: {data.summary_stats.high} | "
        f"Medium: {data.summary_stats.medium} | Low: {data.summary_stats.low} | "
        f"Info: {data.summary_stats.info}",
        "",
        "## Findings",
        "Generate one complete report per finding below. Separate each report with `---`.",
        "",
    ]

    for i, fg in enumerate(data.finding_groups, 1):
        sections.append(f"### Finding {i}: {fg.title}")
        sections.append(f"- Severity: {fg.severity} (CVSS: {fg.cvss_score})")
        sections.append(f"- Source tool: {fg.source_tool}")
        if fg.description:
            sections.append(f"- Description: {fg.description}")
        if fg.remediation:
            sections.append(f"- Remediation hint: {fg.remediation}")
        sections.append("- Affected assets:")
        for asset in fg.affected_assets:
            sections.append(f"  - {asset.asset_value} (port {asset.port}/{asset.protocol})")
            if asset.poc:
                sections.append(f"  - PoC: ```\n{asset.poc}\n```")
        sections.append("")

    return "\n".join(sections)


__all__ = ["SYSTEM_PROMPT", "build_report_prompt", "PLATFORM_GUIDANCE"]
