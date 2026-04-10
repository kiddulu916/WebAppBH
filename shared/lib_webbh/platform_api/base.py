"""Abstract base for all bug bounty platform API clients."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ScopeEntry:
    """Normalized scope entry from any platform."""
    asset_type: str      # domain, ip, wildcard, cidr, mobile_app, etc.
    asset_value: str
    eligible_for_bounty: bool
    max_severity: str | None = None


@dataclass
class SubmissionResult:
    """Result of submitting a report to a platform."""
    external_id: str
    status: str
    platform_url: str | None = None
    raw_response: dict | None = None


class PlatformClient(ABC):
    """Abstract base for platform API clients."""

    @abstractmethod
    async def import_scope(self, program_handle: str) -> list[ScopeEntry]:
        """Fetch the program's scope from the platform."""
        ...

    @abstractmethod
    async def submit_report(
        self,
        program_handle: str,
        title: str,
        body: str,
        severity: str,
        **kwargs,
    ) -> SubmissionResult:
        """Submit a vulnerability report and return the external ID."""
        ...

    @abstractmethod
    async def sync_status(self, external_id: str) -> str:
        """Return the current status of a submitted report."""
        ...
