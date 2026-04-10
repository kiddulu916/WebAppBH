"""Vulnerability reasoning analyzer — batch LLM analysis with 10 dimensions."""
from __future__ import annotations

import json
from typing import Any, Iterator

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from lib_webbh import setup_logger
from lib_webbh.database import (
    Target,
    Vulnerability,
    Asset,
    Observation,
    VulnerabilityInsight,
)
from lib_webbh.llm_client import LLMClient
from lib_webbh.prompts.reasoning import REASONING_SYSTEM, build_reasoning_prompt
from lib_webbh.messaging import push_task

logger = setup_logger("reasoning_analyzer")


def chunk_vulns(vulns: list, batch_size: int = 10) -> Iterator[list]:
    """Yield successive batches of vulns."""
    for i in range(0, len(vulns), batch_size):
        yield vulns[i : i + batch_size]


def parse_llm_response(response_text: str) -> list[dict]:
    """Parse the LLM JSON response into a list of insight dicts."""
    try:
        data = json.loads(response_text)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse LLM response as JSON")
        return []

    insights = data.get("insights")
    if not isinstance(insights, list):
        logger.warning("LLM response missing 'insights' array")
        return []

    return insights


async def query_target_context(
    session: AsyncSession, target_id: int
) -> tuple[dict, list[dict]]:
    """Load target info and all vulns with asset/observation context."""
    target = (
        await session.execute(select(Target).where(Target.id == target_id))
    ).scalar_one_or_none()

    if target is None:
        return {}, []

    target_info = {
        "target_id": target_id,
        "domain": target.base_domain,
        "tech_stack": [],
        "platform": (target.target_profile or {}).get("platform", "unknown"),
    }

    # Get tech stack from observations
    obs_rows = (
        await session.execute(
            select(Observation).where(Observation.target_id == target_id)
        )
    ).scalars().all()

    for obs in obs_rows:
        if obs.observation_value:
            target_info["tech_stack"].append(obs.observation_value)

    # Get all vulns
    vuln_rows = (
        await session.execute(
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .order_by(Vulnerability.cvss_score.desc().nulls_last())
        )
    ).scalars().all()

    vulns = []
    for v in vuln_rows:
        asset_value = None
        if v.asset_id:
            asset = (
                await session.execute(select(Asset).where(Asset.id == v.asset_id))
            ).scalar_one_or_none()
            if asset:
                asset_value = asset.asset_value

        vulns.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "description": v.description,
            "poc": v.poc,
            "source_tool": v.source_tool,
            "asset_value": asset_value or target.base_domain,
            "observations": [],
        })

    return target_info, vulns


def _build_insight(
    target_id: int,
    raw: dict,
    raw_text: str,
) -> VulnerabilityInsight:
    """Map a parsed insight dict to a VulnerabilityInsight ORM object."""
    return VulnerabilityInsight(
        target_id=target_id,
        vulnerability_id=raw["vulnerability_id"],
        severity_assessment=raw.get("severity_assessment"),
        exploitability=raw.get("exploitability"),
        false_positive_likelihood=float(raw.get("false_positive_likelihood", 0.0)),
        chain_hypotheses=raw.get("chain_hypotheses"),
        next_steps=raw.get("next_steps"),
        bounty_estimate=raw.get("bounty_estimate"),
        duplicate_likelihood=float(raw.get("duplicate_likelihood", 0.0)),
        owasp_cwe=raw.get("owasp_cwe"),
        report_readiness_score=float(raw.get("report_readiness_score", 0.0)),
        report_readiness_notes=raw.get("report_readiness_notes"),
        asset_criticality=raw.get("asset_criticality"),
        asset_criticality_rationale=raw.get("asset_criticality_rationale"),
        confidence=float(raw.get("confidence", 0.5)),
        raw_analysis=raw_text,
    )


async def analyze_findings(
    target_id: int,
    session: AsyncSession,
    llm_client: LLMClient | None = None,
) -> int:
    """Run LLM analysis on all findings for a target. Returns insight count."""
    log = logger.bind(target_id=target_id)
    client = llm_client or LLMClient()

    target_info, vulns = await query_target_context(session, target_id)
    if not vulns:
        log.info("No vulnerabilities to analyze")
        return 0

    total_insights = 0

    for batch in chunk_vulns(vulns, batch_size=10):
        prompt = build_reasoning_prompt(target_info, batch)
        response = await client.generate(
            prompt=prompt,
            system=REASONING_SYSTEM,
            json_mode=True,
            temperature=0.2,
        )

        parsed = parse_llm_response(response.text)
        if not parsed:
            log.warning("Empty parse result for batch", extra={"batch_size": len(batch)})
            continue

        for raw in parsed:
            if "vulnerability_id" not in raw:
                continue
            insight = _build_insight(target_id, raw, response.text)
            session.add(insight)
            total_insights += 1

        await session.commit()
        log.info("Batch analyzed", extra={"batch_size": len(batch), "insights": len(parsed)})

    # Publish SSE event
    try:
        await push_task(f"events:{target_id}", {
            "event": "REASONING_COMPLETE",
            "target_id": target_id,
            "insight_count": total_insights,
        })
    except Exception:
        log.warning("Failed to publish REASONING_COMPLETE event")

    log.info("Analysis complete", extra={"total_insights": total_insights})
    return total_insights
