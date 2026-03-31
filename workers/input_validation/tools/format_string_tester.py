"""Format string testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class FormatStringTester(InputValidationTool):
    """Test for format string vulnerabilities."""

    name = "format_string_tester"
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
        """Execute format string tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)
        payloads = ["%s%s%s%s%s%s", "%x%x%x%x", "%n%n%n"]

        for asset_id, url in urls:
            for payload in payloads:
                test_url = f"{url}?input={payload}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=headers, timeout=10) as resp:
                            response_text = await resp.text()
                            if any(indicator in response_text.lower() for indicator in ["segmentation fault", "format error", "invalid format"]):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="Format String Vulnerability",
                                    description=f"Format string vulnerability found at {url}",
                                    poc=test_url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}