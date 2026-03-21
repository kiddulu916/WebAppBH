"""Stage 2: Deduplicate findings and enrich with CVSS/remediation."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from workers.reporting_worker.models import (
    AffectedAsset,
    FindingGroup,
    ReportData,
    ReportContext,
    SummaryStats,
)
from workers.reporting_worker.remediation import lookup_remediation

SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
    "informational": 0.0,
}


def deduplicate_and_enrich(ctx: ReportContext, platform: str, formats: list[str]) -> ReportData:
    """Group vulns by (source_tool, title, severity), enrich, and return ReportData."""
    groups_map: dict[tuple[str | None, str, str], list[Any]] = defaultdict(list)

    for v in ctx.vulnerabilities:
        key = (v.source_tool, v.title, v.severity)
        groups_map[key].append(v)

    finding_groups: list[FindingGroup] = []
    severity_counts: dict[str, int] = defaultdict(int)

    for (source_tool, title, severity), vulns in groups_map.items():
        first = vulns[0]
        cvss = first.cvss_score if first.cvss_score is not None else SEVERITY_CVSS.get(severity.lower(), 0.0)
        remediation = first.remediation if first.remediation else lookup_remediation(title)

        affected: list[AffectedAsset] = []
        for v in vulns:
            if v.asset:
                loc = v.asset.locations[0] if v.asset.locations else None
                affected.append(AffectedAsset(
                    asset_value=v.asset.asset_value,
                    port=loc.port if loc else None,
                    protocol=loc.protocol if loc else None,
                    service=loc.service if loc else None,
                    poc=v.poc,
                    screenshot_paths=ctx.screenshot_map.get(v.asset_id, []),
                ))
            else:
                affected.append(AffectedAsset(
                    asset_value="(target-wide)",
                    poc=v.poc,
                ))

        finding_groups.append(FindingGroup(
            title=title,
            severity=severity,
            cvss_score=cvss,
            description=first.description,
            remediation=remediation,
            source_tool=source_tool,
            affected_assets=affected,
        ))
        severity_counts[severity.lower()] += 1

    finding_groups.sort(key=lambda g: g.cvss_score, reverse=True)

    stats = SummaryStats(
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0) + severity_counts.get("informational", 0),
    )

    return ReportData(
        company_name=ctx.company_name,
        base_domain=ctx.base_domain,
        finding_groups=finding_groups,
        summary_stats=stats,
        generation_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        platform=platform,
        formats=formats,
        assets=ctx.assets,
        cloud_assets=ctx.cloud_assets,
        api_schemas=ctx.api_schemas,
    )
