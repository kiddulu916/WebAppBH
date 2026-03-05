"""CspAnalyzer — Stage 4 Content-Security-Policy analysis.

Fetches live URLs and inspects the Content-Security-Policy header for
missing or weak directives, flagging issues as vulnerabilities.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("csp-analyzer")

# (value_to_find, directive_to_check, severity)
CSP_WEAKNESSES: list[tuple[str, str, str]] = [
    ("unsafe-inline", "script-src", "high"),
    ("unsafe-eval", "script-src", "high"),
    ("*", "script-src", "high"),
    ("*", "default-src", "high"),
    ("data:", "script-src", "medium"),
    ("http:", "script-src", "medium"),
]


class CspAnalyzer(WebAppTool):
    """Detect missing or weak Content-Security-Policy headers."""

    name = "csp_analyzer"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _parse_csp(csp_header: str) -> dict[str, list[str]]:
        """Parse CSP header into {directive: [values]} dict."""
        directives: dict[str, list[str]] = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives[tokens[0]] = tokens[1:] if len(tokens) > 1 else []
        return directives

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Check CSP headers on live URLs.

        Returns a stats dict with keys: urls_checked, csp_missing,
        csp_weak, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="csp")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping csp_analyzer -- within cooldown period")
            return {
                "urls_checked": 0,
                "csp_missing": 0,
                "csp_weak": 0,
                "skipped_cooldown": True,
            }

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {
                "urls_checked": 0,
                "csp_missing": 0,
                "csp_weak": 0,
                "skipped_cooldown": False,
            }

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
        csp_missing = 0
        csp_weak = 0

        try:
            for asset_id, domain in urls:
                try:
                    resp = await client.get(f"https://{domain}")
                    urls_checked += 1

                    # Look for CSP header (case-insensitive)
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    csp_value = resp_headers.get("content-security-policy")

                    if not csp_value:
                        # No CSP header at all
                        csp_missing += 1
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"No CSP header on {domain}",
                            description=(
                                f"The response from {domain} does not include a "
                                f"Content-Security-Policy header. This leaves the "
                                f"site more vulnerable to XSS and data injection "
                                f"attacks."
                            ),
                        )
                        continue

                    # Parse and check for weaknesses
                    directives = self._parse_csp(csp_value)

                    for weakness_value, directive, severity in CSP_WEAKNESSES:
                        values = directives.get(directive, [])
                        if any(weakness_value in v for v in values):
                            csp_weak += 1
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity=severity,
                                title=(
                                    f"Weak CSP: '{weakness_value}' in "
                                    f"{directive} on {domain}"
                                ),
                                description=(
                                    f"The Content-Security-Policy on {domain} "
                                    f"contains '{weakness_value}' in the "
                                    f"{directive} directive, which weakens XSS "
                                    f"protection."
                                ),
                            )

                    # Check for missing frame-ancestors
                    if "frame-ancestors" not in directives:
                        csp_weak += 1
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"CSP missing frame-ancestors on {domain}",
                            description=(
                                f"The Content-Security-Policy on {domain} does "
                                f"not include a frame-ancestors directive, "
                                f"leaving the page vulnerable to clickjacking."
                            ),
                        )

                    # Check for missing object-src
                    if "object-src" not in directives:
                        csp_weak += 1
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="low",
                            title=f"CSP missing object-src on {domain}",
                            description=(
                                f"The Content-Security-Policy on {domain} does "
                                f"not include an object-src directive, allowing "
                                f"plugin content to load from any source."
                            ),
                        )

                except Exception as exc:
                    log.warning(
                        f"Failed to check CSP on {domain}: {exc}",
                        extra={"domain": domain},
                    )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "csp_missing": csp_missing,
            "csp_weak": csp_weak,
            "skipped_cooldown": False,
        }
        log.info("csp_analyzer complete", extra=stats)
        return stats
