"""Stored XSS testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class StoredXssTester(InputValidationTool):
    """Test for stored XSS vulnerabilities."""

    name = "stored_xss_tester"
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
        """Execute stored XSS tests against target URLs."""
        found = 0
        vulnerable = 0

        # Get URLs to test (forms that might store data)
        urls = await self._get_all_url_assets(target_id)
        payloads = self.get_injection_payloads("xss")

        for asset_id, url in urls:
            # For stored XSS, we'd need to POST data and then check if it appears
            # This is a simplified version - in practice, need form detection
            for payload in payloads:
                try:
                    async with aiohttp.ClientSession() as session:
                        # Try POST with payload
                        data = {"comment": payload, "message": payload}
                        async with session.post(url, data=data, headers=headers, timeout=10) as resp:
                            if resp.status == 200:
                                # Check response for reflection (simplified)
                                response_text = await resp.text()
                                if payload in response_text:
                                    await self._save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity="high",
                                        title="Potential Stored XSS Vulnerability",
                                        description=f"Stored XSS payload reflected at {url}",
                                        poc=url,
                                    )
                                    vulnerable += 1
                                    break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}