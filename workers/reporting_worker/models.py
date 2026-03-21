"""Dataclasses for the reporting pipeline."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def sanitize_filename(name: str) -> str:
    """Strip unsafe characters from a string for use in filenames."""
    return re.sub(r'[^\w\-.]', '_', name)


@dataclass
class AffectedAsset:
    asset_value: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    poc: str | None = None
    screenshot_paths: list[str] = field(default_factory=list)


@dataclass
class FindingGroup:
    title: str
    severity: str
    cvss_score: float
    description: str | None
    remediation: str | None
    source_tool: str | None
    affected_assets: list[AffectedAsset] = field(default_factory=list)


@dataclass
class SummaryStats:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total_findings(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


@dataclass
class ReportContext:
    target_id: int
    company_name: str
    base_domain: str
    target_profile: dict[str, Any]
    vulnerabilities: list[Any]
    assets: list[Any]
    locations: list[Any]
    observations: list[Any]
    cloud_assets: list[Any]
    api_schemas: list[Any]
    screenshot_map: dict[int, list[str]] = field(default_factory=dict)


@dataclass
class ReportData:
    company_name: str
    base_domain: str
    finding_groups: list[FindingGroup]
    summary_stats: SummaryStats
    generation_date: str
    platform: str
    formats: list[str]
    assets: list[Any] = field(default_factory=list)
    cloud_assets: list[Any] = field(default_factory=list)
    api_schemas: list[Any] = field(default_factory=list)
