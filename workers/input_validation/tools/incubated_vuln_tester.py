"""Incubated vulnerability testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass

INCUBATED_PAYLOADS = [
    "sleep(10)",
    "waitfor delay '0:0:10'",
    "pg_sleep(10)",
    "dbms_pipe.receive_message(('a'),10)",
    "SELECT SLEEP(10)",
]


class IncubatedVulnTester(InputValidationTool):
    """Test for incubated/time-based vulnerabilities."""

    name = "incubated_vuln"
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
        """Execute incubated vulnerability tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            for payload in INCUBATED_PAYLOADS:
                test_url = f"{url}?input={payload}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=headers, timeout=15) as resp:
                            response_text = await resp.text()
                            if self.detect_vulnerability(response_text, "incubated"):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="Incubated Vulnerability Detected",
                                    description=f"Incubated vulnerability found at {url} with payload: {payload}",
                                    poc=test_url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}
