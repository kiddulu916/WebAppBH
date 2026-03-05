"""VersionFingerprinter -- Stage 4 HTTP server version disclosure detection.

Checks live URLs for version information leaked through HTTP headers
(Server, X-Powered-By, X-AspNet-Version, X-Generator) and HTML meta
generator tags, flagging each disclosure as a low-severity vulnerability.
"""

from __future__ import annotations

import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("version-fingerprinter")

# Headers commonly leaking version information.
VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

# Regex to extract <meta name="generator" content="..."> from HTML.
META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class VersionFingerprinter(WebAppTool):
    """Detect server and framework version disclosure on live web pages."""

    name = "version_fingerprinter"
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
        """Check live URLs for version disclosure in headers and HTML.

        Returns a stats dict with keys: urls_checked, versions_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="version")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping version_fingerprinter -- within cooldown period")
            return {"urls_checked": 0, "versions_found": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "versions_found": 0, "skipped_cooldown": False}

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
        versions_found = 0

        try:
            for asset_id, domain in urls:
                try:
                    resp = await client.get(f"https://{domain}")
                    resp_headers = dict(resp.headers)
                    urls_checked += 1

                    tech_stack: dict[str, str] = {}

                    # -- Check headers for version info --
                    for hdr in VERSION_HEADERS:
                        value = resp_headers.get(hdr, "")
                        if not value:
                            # Try case-insensitive lookup
                            lower_headers = {
                                k.lower(): v for k, v in resp_headers.items()
                            }
                            value = lower_headers.get(hdr, "")
                        if value:
                            tech_stack[hdr] = value
                            versions_found += 1

                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="low",
                                title=f"Server version disclosure via {hdr} on {domain}",
                                description=(
                                    f"The {hdr} header on {domain} discloses "
                                    f"version information: {value}"
                                ),
                            )

                    # -- Check HTML for meta generator tags --
                    body = resp.text
                    match = META_GENERATOR_RE.search(body)
                    if match:
                        generator = match.group(1)
                        tech_stack["generator"] = generator
                        versions_found += 1

                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="low",
                            title=f"Generator meta tag disclosure on {domain}",
                            description=(
                                f"The HTML on {domain} contains a meta generator "
                                f"tag disclosing: {generator}"
                            ),
                        )

                    # Save observation with tech_stack dict
                    await self._save_observation(
                        asset_id=asset_id,
                        status_code=resp.status_code,
                        page_title=None,
                        tech_stack=tech_stack if tech_stack else None,
                        headers=resp_headers,
                    )

                except Exception as exc:
                    log.warning(
                        f"Failed to check versions on {domain}: {exc}",
                        extra={"domain": domain},
                    )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "versions_found": versions_found,
            "skipped_cooldown": False,
        }
        log.info("version_fingerprinter complete", extra=stats)
        return stats
