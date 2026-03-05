"""CookieAuditor — Stage 4 HTTP cookie security analysis.

Parses Set-Cookie headers from live URLs and flags cookies missing
Secure, HttpOnly, or SameSite attributes.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("cookie-auditor")


class CookieAuditor(WebAppTool):
    """Detect insecure cookie attributes on live web pages."""

    name = "cookie_auditor"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _check_cookie(set_cookie_str: str) -> list[str]:
        """Return a list of security issues for a Set-Cookie header value.

        Checks for missing Secure, HttpOnly, and SameSite attributes.
        """
        lower = set_cookie_str.lower()
        issues: list[str] = []

        if "secure" not in lower:
            issues.append("Missing Secure flag")
        if "httponly" not in lower:
            issues.append("Missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("Missing SameSite attribute")

        return issues

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Check cookie security attributes on live URLs.

        Returns a stats dict with keys: urls_checked, insecure_cookies,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="cookies")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping cookie_auditor — within cooldown period")
            return {"urls_checked": 0, "insecure_cookies": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "insecure_cookies": 0, "skipped_cooldown": False}

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
        insecure_count = 0

        try:
            for asset_id, domain in urls:
                try:
                    resp = await client.get(f"https://{domain}")
                    urls_checked += 1

                    # httpx returns multiple set-cookie via headers.get_list
                    cookie_headers = resp.headers.multi_items()
                    for name, value in cookie_headers:
                        if name.lower() != "set-cookie":
                            continue

                        cookie_name = value.split("=", 1)[0].strip()
                        issues = self._check_cookie(value)

                        if issues:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title=f"Insecure cookie '{cookie_name}' on {domain}",
                                description=(
                                    f"The cookie '{cookie_name}' on {domain} "
                                    f"has the following issues: "
                                    f"{', '.join(issues)}."
                                ),
                            )
                            insecure_count += 1

                except Exception as exc:
                    log.warning(
                        f"Failed to check cookies on {domain}: {exc}",
                        extra={"domain": domain},
                    )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "insecure_cookies": insecure_count,
            "skipped_cooldown": False,
        }
        log.info("cookie_auditor complete", extra=stats)
        return stats
