"""SSRF testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class SsrfTester(InputValidationTool):
    """Test for server-side request forgery vulnerabilities."""

    name = "ssrf_tester"
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
        """Execute SSRF tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)
        payloads = ["http://127.0.0.1:80", "http://localhost:8080", "http://169.254.169.254/latest/meta-data/"]

        for asset_id, url in urls:
            for payload in payloads:
                test_url = f"{url}?url={payload}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=headers, timeout=10) as resp:
                            response_text = await resp.text()
                            # Check for internal service responses or metadata
                            if any(indicator in response_text.lower() for indicator in ["ami-id", "instance-id", "localhost", "127.0.0.1"]):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="Server-Side Request Forgery",
                                    description=f"SSRF vulnerability found at {url} with payload: {payload}",
                                    poc=test_url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}