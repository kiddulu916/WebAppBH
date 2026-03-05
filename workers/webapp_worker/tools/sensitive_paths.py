"""SensitivePaths — Stage 5 sensitive file/path discovery.

Probes a curated wordlist of paths known to leak configuration, source
code, or administrative functionality.
"""

from __future__ import annotations

import asyncio

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("sensitive-paths")

# Paths to probe on each live domain.
SENSITIVE_WORDLIST: list[str] = [
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/wp-config.php",
    "/admin",
    "/debug",
    "/actuator/health",
    "/.htpasswd",
    "/server-status",
    "/phpinfo.php",
    "/backup.sql",
    "/.svn/entries",
    "/config.yml",
    "/.dockerenv",
    "/api/swagger",
    "/elmah.axd",
    "/trace.axd",
    "/web.config",
    "/.well-known/security.txt",
    "/crossdomain.xml",
]

# Paths that warrant critical severity when accessible.
CRITICAL_PATHS = {".git", ".env", ".htpasswd", "wp-config.php", "web.config"}


class SensitivePaths(WebAppTool):
    """Discover sensitive files and paths on live web servers."""

    name = "sensitive_paths"
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
        """Probe sensitive paths on live URLs.

        Returns a stats dict with keys: urls_checked, paths_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="sensitive_paths")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping sensitive_paths — within cooldown period")
            return {"urls_checked": 0, "paths_found": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "paths_found": 0, "skipped_cooldown": False}

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
        paths_found = 0

        try:
            for asset_id, domain in urls:
                base_url = f"https://{domain}"

                async def _probe(path: str) -> tuple[str, int | None]:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        return path, resp.status_code
                    except Exception:
                        return path, None

                results = await asyncio.gather(
                    *[_probe(p) for p in SENSITIVE_WORDLIST]
                )
                urls_checked += 1

                for path, status in results:
                    if status is None:
                        continue
                    if status not in (200, 403):
                        continue

                    paths_found += 1

                    # Determine severity
                    path_base = path.lstrip("/").split("/")[0]
                    severity = "critical" if path_base in CRITICAL_PATHS else "medium"

                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity=severity,
                        title=f"Sensitive path accessible: {path} on {domain}",
                        description=(
                            f"The path {path} on {domain} returned HTTP "
                            f"{status}. This may expose sensitive configuration, "
                            f"source code, or administrative functionality."
                        ),
                        poc=f"{base_url}{path}",
                    )

                    # Save as asset
                    await self._save_asset(
                        target_id=target_id,
                        url=f"{base_url}{path}",
                        scope_manager=scope_manager,
                        source_tool=self.name,
                    )

        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "paths_found": paths_found,
            "skipped_cooldown": False,
        }
        log.info("sensitive_paths complete", extra=stats)
        return stats
