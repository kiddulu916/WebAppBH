"""YesWeHack API client."""
from __future__ import annotations

import os

import httpx

from lib_webbh.platform_api.base import PlatformClient, ScopeEntry, SubmissionResult

BASE_URL = "https://apps.yeswehack.com/api"
DEFAULT_TIMEOUT = 30.0


class YesWeHackClient(PlatformClient):
    """Client for YesWeHack's API."""

    def __init__(self, api_token: str | None = None):
        self._token = api_token or os.environ.get("YESWEHACK_API_TOKEN", "")

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
        for s in data.get("scopes", []):
            entries.append(ScopeEntry(
                asset_type=s.get("scope_type", "unknown").lower(),
                asset_value=s.get("scope", ""),
                eligible_for_bounty=not s.get("out_of_scope", True),
                max_severity=None,
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
            "vulnerability_type": kwargs.get("vuln_type", ""),
        }

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.post(
                f"{BASE_URL}/programs/{program_handle}/reports",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        return SubmissionResult(
            external_id=str(data.get("id", "")),
            status=data.get("status", {}).get("workflow_state", "unknown")
            if isinstance(data.get("status"), dict) else str(data.get("status", "unknown")),
            raw_response=data,
        )

    async def sync_status(self, external_id: str) -> str:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.get(
                f"{BASE_URL}/reports/{external_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        status = data.get("status", {})
        if isinstance(status, dict):
            return status.get("workflow_state", "unknown")
        return str(status)
