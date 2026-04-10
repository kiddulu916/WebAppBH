"""HackerOne API client."""
from __future__ import annotations

import os

import httpx

from lib_webbh.platform_api.base import PlatformClient, ScopeEntry, SubmissionResult

BASE_URL = "https://api.hackerone.com/v1"
DEFAULT_TIMEOUT = 30.0


class HackerOneClient(PlatformClient):
    """Client for HackerOne's API v1."""

    def __init__(
        self,
        api_token: str | None = None,
        api_username: str | None = None,
    ):
        self._token = api_token or os.environ.get("HACKERONE_API_TOKEN", "")
        self._username = api_username or os.environ.get("HACKERONE_API_USERNAME", "")

    def _auth(self) -> tuple[str, str]:
        return (self._username, self._token)

    async def import_scope(self, program_handle: str) -> list[ScopeEntry]:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.get(
                f"{BASE_URL}/programs/{program_handle}",
                auth=self._auth(),
            )
            resp.raise_for_status()
            data = resp.json()

        scopes_data = (
            data.get("relationships", {})
            .get("structured_scopes", {})
            .get("data", [])
        )

        entries = []
        for s in scopes_data:
            attrs = s.get("attributes", {})
            entries.append(ScopeEntry(
                asset_type=attrs.get("asset_type", "unknown").lower(),
                asset_value=attrs.get("asset_identifier", ""),
                eligible_for_bounty=attrs.get("eligible_for_bounty", False),
                max_severity=attrs.get("max_severity_rating"),
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
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": title,
                    "vulnerability_information": body,
                    "severity_rating": severity,
                },
            }
        }

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.post(
                f"{BASE_URL}/reports",
                json=payload,
                auth=self._auth(),
            )
            resp.raise_for_status()
            data = resp.json()

        report = data.get("data", {})
        return SubmissionResult(
            external_id=str(report.get("id", "")),
            status=report.get("attributes", {}).get("state", "unknown"),
            platform_url=f"https://hackerone.com/reports/{report.get('id', '')}",
            raw_response=data,
        )

    async def sync_status(self, external_id: str) -> str:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.get(
                f"{BASE_URL}/reports/{external_id}",
                auth=self._auth(),
            )
            resp.raise_for_status()
            data = resp.json()

        return data.get("data", {}).get("attributes", {}).get("state", "unknown")
