"""HTTP verb tampering testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class HttpVerbTamperTester(InputValidationTool):
    """Test for HTTP verb tampering vulnerabilities."""

    name = "http_verb_tamper_tester"
    weight_class = WeightClass.LIGHT

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Execute HTTP verb tampering tests against target URLs."""
        found = 0
        vulnerable = 0

        # Get URLs to test
        urls = await self._get_all_url_assets(target_id)
        verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]

        for asset_id, url in urls:
            for verb in verbs:
                try:
                    async with aiohttp.ClientSession() as session:
                        # Use the appropriate method
                        method_func = getattr(session, verb.lower())
                        async with method_func(url, headers=headers, timeout=10) as resp:
                            # Check if verb is accepted when it shouldn't be
                            if resp.status not in [405, 501]:  # Method Not Allowed or Not Implemented
                                # If unusual verb succeeds, might be vulnerable
                                if verb in ["TRACE", "TRACK"] and resp.status == 200:
                                    await self._save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity="medium",
                                        title="HTTP Verb Tampering Vulnerability",
                                        description=f"HTTP {verb} method accepted at {url}",
                                        poc=f"{verb} {url}",
                                    )
                                    vulnerable += 1
                                    break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}