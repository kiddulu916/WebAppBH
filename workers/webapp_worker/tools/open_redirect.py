"""OpenRedirect — Stage 5 open redirect detection.

Tests common redirect parameters with an attacker-controlled URL to
detect open redirect vulnerabilities.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("open-redirect")

# Common parameter names used for redirects.
REDIRECT_PARAMS = [
    "redirect",
    "url",
    "next",
    "return",
    "returnTo",
    "goto",
    "redirect_uri",
    "continue",
    "dest",
    "destination",
    "rurl",
    "target",
]

# Canary URL used to test for open redirects.
CANARY_URL = "https://attacker.com/canary"


class OpenRedirect(WebAppTool):
    """Detect open redirect vulnerabilities via common redirect parameters."""

    name = "open_redirect"
    tool_type = ToolType.HTTP
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
        """Test redirect parameters on live URLs.

        Returns a stats dict with keys: urls_checked, redirects_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="open_redirect")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping open_redirect — within cooldown period")
            return {"urls_checked": 0, "redirects_found": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "redirects_found": 0, "skipped_cooldown": False}

        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=False,
            )
            should_close = True

        urls_checked = 0
        redirects_found = 0

        try:
            for asset_id, domain in urls:
                base_url = f"https://{domain}"
                urls_checked += 1

                for param in REDIRECT_PARAMS:
                    test_url = f"{base_url}/?{param}={CANARY_URL}"
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code in (301, 302, 303, 307, 308):
                            location = resp.headers.get("location", "")
                            if "attacker.com" in location:
                                redirects_found += 1
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="medium",
                                    title=f"Open redirect via '{param}' on {domain}",
                                    description=(
                                        f"The parameter '{param}' on {domain} "
                                        f"redirects to an attacker-controlled URL. "
                                        f"Location header: {location}"
                                    ),
                                    poc=test_url,
                                )

                    except Exception as exc:
                        log.debug(
                            f"Redirect test failed for {domain}?{param}: {exc}"
                        )

        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "redirects_found": redirects_found,
            "skipped_cooldown": False,
        }
        log.info("open_redirect complete", extra=stats)
        return stats
