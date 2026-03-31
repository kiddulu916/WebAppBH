"""Host header injection testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class HostHeaderTester(InputValidationTool):
    """Test for host header injection vulnerabilities."""

    name = "host_header_tester"
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
        """Execute host header injection tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)
        malicious_hosts = ["evil.com", "127.0.0.1", "localhost"]

        for asset_id, url in urls:
            for host in malicious_hosts:
                try:
                    custom_headers = (headers or {}).copy()
                    custom_headers["Host"] = host
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers=custom_headers, timeout=10) as resp:
                            # Check if host header is reflected in response
                            response_text = await resp.text()
                            if host in response_text:
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="medium",
                                    title="Host Header Injection Vulnerability",
                                    description=f"Host header injection found at {url} with host: {host}",
                                    poc=url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}