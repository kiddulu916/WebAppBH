"""HTTP parameter pollution testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class HttpParameterPollutionTester(InputValidationTool):
    """Test for HTTP parameter pollution vulnerabilities."""

    name = "http_parameter_pollution_tester"
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
        """Execute HTTP parameter pollution tests against target URLs."""
        found = 0
        vulnerable = 0

        # Get URLs to test
        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            # Test parameter pollution: param=value&param=evil
            test_url = f"{url}?id=123&id=456"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, headers=headers, timeout=10) as resp:
                        response_text = await resp.text()
                        # If both values are processed, might be vulnerable
                        if "123" in response_text and "456" in response_text:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title="HTTP Parameter Pollution Vulnerability",
                                description=f"Parameter pollution possible at {url}",
                                poc=test_url,
                            )
                            vulnerable += 1
            except Exception:
                pass
            found += 1

        return {"found": found, "vulnerable": vulnerable}