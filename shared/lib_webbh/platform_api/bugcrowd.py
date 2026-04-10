"""Bugcrowd API client."""
from __future__ import annotations

import os

import httpx

from lib_webbh.platform_api.base import PlatformClient, ScopeEntry, SubmissionResult

BASE_URL = "https://api.bugcrowd.com"
DEFAULT_TIMEOUT = 30.0


class BugcrowdClient(PlatformClient):
    """Client for Bugcrowd's API."""

    def __init__(self, api_token: str | None = None):
        self._token = api_token or os.environ.get("BUGCROWD_API_TOKEN", "")

    def _headers(self) -> dict:
        return {"Authorization": f"Token {self._token}", "Accept": "application/vnd.bugcrowd+json"}

    async def import_scope(self, program_handle: str) -> list[ScopeEntry]:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.get(
                f"{BASE_URL}/bounties/{program_handle}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        entries = []
        target_groups = (
            data.get("data", {})
            .get("relationships", {})
            .get("target_groups", {})
            .get("data", [])
        )

        for group in target_groups:
            targets = (
                group.get("relationships", {})
                .get("targets", {})
                .get("data", [])
            )
            for t in targets:
                attrs = t.get("attributes", {})
                entries.append(ScopeEntry(
                    asset_type=attrs.get("category", "unknown").lower(),
                    asset_value=attrs.get("name", ""),
                    eligible_for_bounty=True,
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
            "data": {
                "type": "submission",
                "attributes": {
                    "title": title,
                    "description": body,
                    "severity": severity,
                    "bug_url": kwargs.get("bug_url", ""),
                },
                "relationships": {
                    "bounty": {"data": {"id": program_handle, "type": "bounty"}}
                },
            }
        }

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as http:
            resp = await http.post(
                f"{BASE_URL}/submissions",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        sub = data.get("data", {})
        return SubmissionResult(
            external_id=str(sub.get("id", "")),
            status=sub.get("attributes", {}).get("state", "new"),
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

        return data.get("data", {}).get("attributes", {}).get("state", "unknown")
