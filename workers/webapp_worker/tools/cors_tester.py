"""CorsTester — Stage 4 CORS misconfiguration detection.

Sends requests with attacker-controlled Origin headers and checks whether
the Access-Control-Allow-Origin header reflects the value, indicating a
CORS misconfiguration that could allow cross-origin data theft.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("cors-tester")

# Origins to test against each URL.
TEST_ORIGINS = ["https://attacker.com", "null"]


class CorsTester(WebAppTool):
    """Detect CORS misconfigurations on live web pages."""

    name = "cors_tester"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _is_cors_misconfigured(
        response_headers: dict[str, str], test_origin: str
    ) -> bool:
        """Return True if response reflects the test origin or allows wildcard with credentials."""
        acao = response_headers.get("access-control-allow-origin", "")
        acac = response_headers.get("access-control-allow-credentials", "").lower()

        # Direct reflection of attacker origin
        if acao == test_origin:
            return True

        # Wildcard with credentials — dangerous combination
        if acao == "*" and acac == "true":
            return True

        # "null" origin reflected (can be triggered via sandboxed iframes)
        if test_origin == "null" and acao == "null":
            return True

        return False

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Test CORS policy on live URLs.

        Returns a stats dict with keys: urls_checked, misconfigurations,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="cors")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping cors_tester — within cooldown period")
            return {"urls_checked": 0, "misconfigurations": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "misconfigurations": 0, "skipped_cooldown": False}

        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=True,
            )
            should_close = True

        urls_checked = 0
        misconfig_count = 0

        try:
            for asset_id, domain in urls:
                url = f"https://{domain}"
                for test_origin in TEST_ORIGINS:
                    try:
                        resp = await client.get(
                            url,
                            headers={"Origin": test_origin},
                        )
                        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                        urls_checked += 1

                        if self._is_cors_misconfigured(resp_headers, test_origin):
                            acao = resp_headers.get("access-control-allow-origin", "")
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title=f"CORS misconfiguration on {domain}",
                                description=(
                                    f"The server at {domain} reflects the Origin "
                                    f"header '{test_origin}' in Access-Control-Allow-Origin "
                                    f"(ACAO: '{acao}'). This allows an attacker to read "
                                    f"responses cross-origin."
                                ),
                                poc=f"curl -H 'Origin: {test_origin}' {url}",
                            )
                            misconfig_count += 1

                    except Exception as exc:
                        log.warning(
                            f"CORS test failed for {domain} with origin {test_origin}: {exc}",
                            extra={"domain": domain},
                        )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "misconfigurations": misconfig_count,
            "skipped_cooldown": False,
        }
        log.info("cors_tester complete", extra=stats)
        return stats
