"""Intigriti API client."""
from __future__ import annotations

import os

import httpx

from lib_webbh.platform_api.base import PlatformClient, ScopeEntry, SubmissionResult

BASE_URL = "https://api.intigriti.com/external/researcher/v1"
DEFAULT_TIMEOUT = 30.0

SEVERITY_MAP = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


class IntigritiClient(PlatformClient):
    """Client for Intigriti's researcher API v1."""

    def __init__(self, api_token: str | None = None):
        self._token = api_token or os.environ.get("INTIGRITI_API_TOKEN", "")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    async def import_scope(self, program_handle: str) -> list[ScopeEntry]:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.get(
                f"{BASE_URL}/programs/{program_handle}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        entries = []
        for d in data.get("domains", []):
            sev_val = d.get("severity", {}).get("value") if isinstance(d.get("severity"), dict) else None
            entries.append(ScopeEntry(
                asset_type=d.get("type", "unknown").lower(),
                asset_value=d.get("endpoint", ""),
                eligible_for_bounty=d.get("bountyEligible", False),
                max_severity=SEVERITY_MAP.get(sev_val) if sev_val is not None else None,
            ))
        return entries

    async def submit_report(
        self,
        program_handle: str,
        title: str,
        body: str,
        severity: str,
        **kwargs,
    ) -> SubmissionResult:
        payload = {
            "title": title,
            "description": body,
            "severity": severity,
            "programId": program_handle,
        }

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.post(
                f"{BASE_URL}/submissions",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        return SubmissionResult(
            external_id=str(data.get("submissionId", "")),
            status=data.get("status", "unknown"),
            raw_response=data,
        )

    async def sync_status(self, external_id: str) -> str:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.get(
                f"{BASE_URL}/submissions/{external_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        return data.get("status", "unknown")
