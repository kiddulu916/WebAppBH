"""SourcemapDetector — Stage 3 source map exposure detection.

Scans saved JavaScript files for sourceMappingURL comments and probes
the corresponding .map URLs. Exposed source maps leak original source
code, file structure, and internal logic.
"""

from __future__ import annotations

import os
import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("sourcemap-detector")

# Base directory for raw JS file storage.  Tests patch this to tmp_path.
JS_DIR = "/app/shared/raw"

# Regex to extract sourceMappingURL from JS files.
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


class SourcemapDetector(WebAppTool):
    """Detect exposed JavaScript source maps."""

    name = "sourcemap_detector"
    tool_type = ToolType.BROWSER
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _get_map_url(js_url: str) -> str:
        """Append ``.map`` to a JavaScript URL."""
        return f"{js_url}.map"

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Scan JS files for sourceMappingURL and probe .map endpoints.

        Returns a stats dict with keys: js_files_scanned, maps_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="sourcemap")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping sourcemap_detector — within cooldown period")
            return {
                "js_files_scanned": 0,
                "maps_found": 0,
                "skipped_cooldown": True,
            }

        js_dir = os.path.join(JS_DIR, str(target_id), "js")
        js_files_scanned = 0
        maps_found = 0
        map_urls_to_probe: list[str] = []

        # 2. Scan saved JS files for sourceMappingURL comments
        if os.path.isdir(js_dir):
            for filename in os.listdir(js_dir):
                if not filename.endswith(".js"):
                    continue
                filepath = os.path.join(js_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except OSError:
                    continue

                js_files_scanned += 1

                # Check for explicit sourceMappingURL
                match = SOURCEMAP_RE.search(content)
                if match:
                    mapping_url = match.group(1)
                    # Handle relative URLs
                    if not mapping_url.startswith(("http://", "https://")):
                        # Get live URLs to build full URL
                        urls = await self._get_live_urls(target_id)
                        if urls:
                            domain = urls[0][1]
                            mapping_url = f"https://{domain}/{mapping_url.lstrip('/')}"
                    map_urls_to_probe.append(mapping_url)

        # 3. Also try appending .map to known JS asset URLs
        urls = await self._get_live_urls(target_id)
        for asset_id, domain in urls:
            # Probe common JS bundle paths
            for filename in os.listdir(js_dir) if os.path.isdir(js_dir) else []:
                if filename.endswith(".js") and not filename.startswith("inline_"):
                    probe = f"https://{domain}/{filename}.map"
                    if probe not in map_urls_to_probe:
                        map_urls_to_probe.append(probe)

        # 4. HTTP probe each .map URL
        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=True,
            )
            should_close = True

        try:
            for map_url in map_urls_to_probe:
                try:
                    resp = await client.get(map_url)
                    if resp.status_code == 200 and "version" in resp.text[:500]:
                        maps_found += 1

                        # Find asset_id for vulnerability
                        asset_id = urls[0][0] if urls else 0
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Source map exposed: {map_url}",
                            description=(
                                f"A JavaScript source map file is publicly accessible "
                                f"at {map_url}. Source maps expose original source "
                                f"code, file paths, and internal application logic."
                            ),
                            poc=map_url,
                        )
                except Exception as exc:
                    log.debug(f"Failed to probe {map_url}: {exc}")
        finally:
            if should_close:
                await client.aclose()

        # 5. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "js_files_scanned": js_files_scanned,
            "maps_found": maps_found,
            "skipped_cooldown": False,
        }
        log.info("sourcemap_detector complete", extra=stats)
        return stats
