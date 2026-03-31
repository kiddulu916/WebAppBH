"""XPath injection testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class XpathInjectionTester(InputValidationTool):
    """Test for XPath injection vulnerabilities."""

    name = "xpath_injection_tester"
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
        """Execute XPath injection tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)
        payloads = ["' or '1'='1", "'] | /* | //*", "admin' and '1'='1"]

        for asset_id, url in urls:
            for payload in payloads:
                test_url = f"{url}?username={payload}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=headers, timeout=10) as resp:
                            response_text = await resp.text()
                            if any(error in response_text.lower() for error in ["xpath", "invalid expression", "query error"]):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="XPath Injection Vulnerability",
                                    description=f"XPath injection found at {url} with payload: {payload}",
                                    poc=test_url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}