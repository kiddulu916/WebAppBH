"""Buffer overflow testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass

BUFFER_OVERFLOW_PAYLOADS = [
    "A" * 1000,
    "A" * 5000,
    "A" * 10000,
    "A" * 50000,
    "%x" * 100,
    "%n" * 100,
]


class BufferOverflowTester(InputValidationTool):
    """Test for buffer overflow vulnerabilities."""

    name = "buffer_overflow"
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
        """Execute buffer overflow tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            for payload in BUFFER_OVERFLOW_PAYLOADS:
                test_url = f"{url}?input={payload}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=headers, timeout=15) as resp:
                            response_text = await resp.text()
                            if self.detect_vulnerability(response_text, "buffer_overflow"):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="critical",
                                    title="Buffer Overflow Vulnerability",
                                    description=f"Buffer overflow found at {url} with payload length: {len(payload)}",
                                    poc=test_url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}
