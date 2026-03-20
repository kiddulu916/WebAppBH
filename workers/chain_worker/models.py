from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChainViability(Enum):
    VIABLE = "viable"
    PARTIAL = "partial"
    NOT_VIABLE = "not_viable"
    AWAITING_ACCOUNTS = "awaiting_accounts"


@dataclass
class ChainStep:
    action: str
    target: str
    result: str
    timestamp: str
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    screenshot_path: str | None = None


@dataclass
class ChainResult:
    success: bool
    steps: list[ChainStep]
    poc: str | None
    chain_name: str
    failure_reason: str | None = None


@dataclass
class EvaluationResult:
    viability: ChainViability
    matched_preconditions: list[str]
    missing_preconditions: list[str] = field(default_factory=list)
    matched_findings: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountCreds:
    username: str
    password: str


@dataclass
class TestAccounts:
    attacker: AccountCreds
    victim: AccountCreds


@dataclass
class TargetFindings:
    target_id: int
    vulnerabilities: list[Any]
    assets: list[Any]
    parameters: list[Any]
    observations: list[Any]
    locations: list[Any]
    test_accounts: TestAccounts | None = None

    def vulns_by_source(self, source_tool: str) -> list[Any]:
        return [v for v in self.vulnerabilities if v.source_tool == source_tool]

    def vulns_by_severity(self, severity: str) -> list[Any]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def vulns_by_title_contains(self, substring: str) -> list[Any]:
        return [v for v in self.vulnerabilities
                if substring.lower() in v.title.lower()]

    def assets_by_type(self, asset_type: str) -> list[Any]:
        return [a for a in self.assets if a.asset_type == asset_type]

    def locations_by_service(self, service: str) -> list[Any]:
        return [loc for loc in self.locations if loc.service == service]
