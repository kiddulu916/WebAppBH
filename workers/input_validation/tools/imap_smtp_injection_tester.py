"""IMAP/SMTP injection testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class ImapSmtpInjectionTester(InputValidationTool):
    """Test for IMAP/SMTP injection vulnerabilities."""

    name = "imap_smtp_injection_tester"
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
        """Execute IMAP/SMTP injection tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)
        payloads = ["\r\nMAIL FROM: attacker@example.com\r\n", "\r\nRCPT TO: victim@example.com\r\n"]

        for asset_id, url in urls:
            for payload in payloads:
                try:
                    data = {"email": f"test@example.com{payload}"}
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url, data=data, headers=headers, timeout=10) as resp:
                            response_text = await resp.text()
                            if "mail" in response_text.lower() or "smtp" in response_text.lower():
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="medium",
                                    title="IMAP/SMTP Injection Vulnerability",
                                    description=f"IMAP/SMTP injection possible at {url}",
                                    poc=url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}