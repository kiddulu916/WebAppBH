"""HTTP request smuggling testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class HttpSmugglingTester(InputValidationTool):
    """Test for HTTP request smuggling vulnerabilities."""

    name = "http_smuggling"
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
        """Execute HTTP smuggling tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)

        smuggling_headers = [
            {"Transfer-Encoding": "chunked", "Content-Length": "0"},
            {"Transfer-Encoding": "identity", "Content-Length": "4"},
            {"Transfer-Encoding": "xchunked", "Content-Length": "0"},
        ]

        for asset_id, url in urls:
            for smuggle_headers in smuggling_headers:
                try:
                    test_headers = {**(headers or {}), **smuggle_headers}
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            url,
                            headers=test_headers,
                            data="X",
                            timeout=10,
                        ) as resp:
                            if resp.status in (400, 502, 504):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="critical",
                                    title="HTTP Request Smuggling Suspected",
                                    description=f"HTTP smuggling indicators found at {url}",
                                    poc=url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}
