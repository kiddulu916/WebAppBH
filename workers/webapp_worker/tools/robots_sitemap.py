"""RobotsSitemap — Stage 5 robots.txt and sitemap.xml parser.

Fetches robots.txt and sitemap.xml from live domains to discover
disallowed paths and indexed URLs for further analysis.
"""

from __future__ import annotations

import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("robots-sitemap")

# Regex to extract Disallow/Allow paths from robots.txt
ROBOTS_PATH_RE = re.compile(r"^(?:Dis)?allow:\s*(\S+)", re.MULTILINE | re.IGNORECASE)

# Regex to extract <loc> URLs from sitemap XML
SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)


class RobotsSitemap(WebAppTool):
    """Parse robots.txt and sitemap.xml to discover paths and URLs."""

    name = "robots_sitemap"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _parse_robots(text: str) -> list[str]:
        """Extract paths from robots.txt content."""
        paths: list[str] = []
        for match in ROBOTS_PATH_RE.finditer(text):
            path = match.group(1).strip()
            if path and path != "/":
                paths.append(path)
        return paths

    @staticmethod
    def _parse_sitemap(xml_text: str) -> list[str]:
        """Extract URLs from sitemap XML content."""
        urls: list[str] = []
        for match in SITEMAP_LOC_RE.finditer(xml_text):
            url = match.group(1).strip()
            if url:
                urls.append(url)
        return urls

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Fetch and parse robots.txt + sitemap.xml.

        Returns a stats dict with keys: urls_checked, robots_paths,
        sitemap_urls, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="robots_sitemap")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping robots_sitemap — within cooldown period")
            return {
                "urls_checked": 0,
                "robots_paths": 0,
                "sitemap_urls": 0,
                "skipped_cooldown": True,
            }

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {
                "urls_checked": 0,
                "robots_paths": 0,
                "sitemap_urls": 0,
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
        total_robots = 0
        total_sitemap = 0

        try:
            for asset_id, domain in urls:
                base_url = f"https://{domain}"
                urls_checked += 1

                # --- robots.txt ---
                try:
                    resp = await client.get(f"{base_url}/robots.txt")
                    if resp.status_code == 200:
                        paths = self._parse_robots(resp.text)
                        total_robots += len(paths)
                        for path in paths:
                            full_url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
                            await self._save_asset(
                                target_id=target_id,
                                url=full_url,
                                scope_manager=scope_manager,
                                source_tool=self.name,
                            )
                except Exception as exc:
                    log.debug(f"Failed to fetch robots.txt from {domain}: {exc}")

                # --- sitemap.xml ---
                try:
                    resp = await client.get(f"{base_url}/sitemap.xml")
                    if resp.status_code == 200:
                        sitemap_urls = self._parse_sitemap(resp.text)
                        total_sitemap += len(sitemap_urls)
                        for url in sitemap_urls:
                            await self._save_asset(
                                target_id=target_id,
                                url=url,
                                scope_manager=scope_manager,
                                source_tool=self.name,
                            )
                except Exception as exc:
                    log.debug(f"Failed to fetch sitemap.xml from {domain}: {exc}")

        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "robots_paths": total_robots,
            "sitemap_urls": total_sitemap,
            "skipped_cooldown": False,
        }
        log.info("robots_sitemap complete", extra=stats)
        return stats
