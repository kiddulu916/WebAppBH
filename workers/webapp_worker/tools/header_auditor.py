"""HeaderAuditor — Stage 4 HTTP security header analysis.

Checks live URLs for the presence of critical security headers and flags
missing ones as medium-severity vulnerabilities.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("header-auditor")

# Security headers that should be present on every response.
REQUIRED_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer leakage protection",
    "Permissions-Policy": "Browser feature restrictions",
}


class HeaderAuditor(WebAppTool):
    """Detect missing security headers on live web pages."""

    name = "header_auditor"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _check_headers(response_headers: dict[str, str]) -> list[str]:
        """Return descriptions for each missing required security header."""
        # Normalise header keys to lower-case for comparison.
        lower = {k.lower(): v for k, v in response_headers.items()}
        missing: list[str] = []
        for header, description in REQUIRED_HEADERS.items():
            if header.lower() not in lower:
                missing.append(f"Missing {header} ({description})")
        return missing

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Check security headers on live URLs.

        Returns a stats dict with keys: urls_checked, missing_headers,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="headers")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping header_auditor — within cooldown period")
            return {"urls_checked": 0, "missing_headers": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "missing_headers": 0, "skipped_cooldown": False}

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
        missing_count = 0

        try:
            for asset_id, domain in urls:
                try:
                    resp = await client.get(f"https://{domain}")
                    resp_headers = dict(resp.headers)
                    urls_checked += 1

                    # Save observation with all response headers
                    await self._save_observation(
                        asset_id=asset_id,
                        status_code=resp.status_code,
                        page_title=None,
                        tech_stack=None,
                        headers=resp_headers,
                    )

                    # Check for missing security headers
                    missing = self._check_headers(resp_headers)
                    for issue in missing:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"{issue} on {domain}",
                            description=(
                                f"The response from {domain} is missing the "
                                f"security header. {issue}."
                            ),
                        )
                        missing_count += 1

                except Exception as exc:
                    log.warning(
                        f"Failed to check headers on {domain}: {exc}",
                        extra={"domain": domain},
                    )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "missing_headers": missing_count,
            "skipped_cooldown": False,
        }
        log.info("header_auditor complete", extra=stats)
        return stats
