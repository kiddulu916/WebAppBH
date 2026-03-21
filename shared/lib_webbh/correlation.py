"""Vulnerability correlation engine."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = {v: k for k, v in SEVERITY_ORDER.items()}

@dataclass
class CorrelationGroup:
    vuln_ids: list[int] = field(default_factory=list)
    shared_assets: list[str] = field(default_factory=list)
    composite_severity: str = "info"
    chain_description: str = ""

def correlate_findings(vulns: list[dict]) -> list[CorrelationGroup]:
    if not vulns:
        return []
    asset_groups: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        asset_value = v.get("asset_value") or "unknown"
        asset_groups[asset_value].append(v)
    groups: list[CorrelationGroup] = []
    for asset_value, group_vulns in asset_groups.items():
        vuln_ids = [v["id"] for v in group_vulns]
        severities = [v.get("severity", "info") for v in group_vulns]
        max_sev = max(SEVERITY_ORDER.get(s, 0) for s in severities)
        titles = [v.get("title", "") for v in group_vulns]
        chain_desc = f"Chain on {asset_value}: {' → '.join(titles)}" if len(titles) > 1 else titles[0]
        groups.append(CorrelationGroup(
            vuln_ids=vuln_ids, shared_assets=[asset_value],
            composite_severity=SEVERITY_NAMES.get(max_sev, "info"), chain_description=chain_desc,
        ))
    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.composite_severity, 0), reverse=True)
    return groups
