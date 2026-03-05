"""LinkFinder — Stage 2 static JS analysis for endpoint extraction.

Reads saved JS files from disk and runs the ``linkfinder`` CLI tool
against each to extract embedded URLs and API endpoints.  Discovered
URLs are scope-checked and persisted as Assets; URL query parameters
are saved as Parameters.
"""

from __future__ import annotations

import glob
import os
from urllib.parse import urlparse, parse_qs

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("linkfinder")

# Base directory for raw JS file storage.  Tests patch this to tmp_path.
JS_DIR = "/app/shared/raw"


class LinkFinder(WebAppTool):
    """Extract endpoints from saved JS files using LinkFinder CLI."""

    name = "linkfinder"
    tool_type = ToolType.CLI
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_output(stdout: str) -> list[str]:
        """Split stdout lines, strip whitespace, filter empty/bracket lines."""
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip lines that are just brackets (JSON wrapper artifacts)
            if line in ("[", "]", "{", "}"):
                continue
            results.append(line)
        return results

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run LinkFinder against all saved JS files for *target_id*.

        Returns a stats dict with keys: endpoints_found, assets_saved,
        params_saved, js_files_processed, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="endpoint")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping linkfinder — within cooldown period")
            return {
                "endpoints_found": 0,
                "assets_saved": 0,
                "params_saved": 0,
                "js_files_processed": 0,
                "skipped_cooldown": True,
            }

        # 2. Glob JS files from disk
        js_dir = os.path.join(JS_DIR, str(target_id), "js")
        js_files = glob.glob(os.path.join(js_dir, "*.js"))
        if not js_files:
            log.info("No JS files found — nothing to analyse")
            return {
                "endpoints_found": 0,
                "assets_saved": 0,
                "params_saved": 0,
                "js_files_processed": 0,
                "skipped_cooldown": False,
            }

        total_endpoints = 0
        total_assets = 0
        total_params = 0

        # 3. Run LinkFinder against each JS file
        for filepath in js_files:
            try:
                stdout = await self.run_subprocess(
                    ["python3", "-m", "linkfinder", "-i", filepath, "-o", "cli"],
                    timeout=60,
                )
            except Exception as exc:
                log.warning(f"linkfinder failed on {filepath}: {exc}")
                continue

            endpoints = self.parse_output(stdout)
            total_endpoints += len(endpoints)

            # 4. Build full URLs and save
            for endpoint in endpoints:
                if endpoint.startswith("http://") or endpoint.startswith("https://"):
                    full_url = endpoint
                else:
                    full_url = f"https://{target.base_domain}{endpoint}"

                # 5. Scope-check and save asset
                asset_id = await self._save_asset(
                    target_id, full_url, scope_manager, source_tool=self.name,
                )
                if asset_id is not None:
                    total_assets += 1

                    # 6. Extract and save URL parameters
                    parsed = urlparse(full_url)
                    params = parse_qs(parsed.query)
                    for param_name, values in params.items():
                        param_value = values[0] if values else None
                        saved = await self._save_parameter(
                            asset_id, param_name, param_value, full_url,
                        )
                        if saved:
                            total_params += 1

        # 7. Update tool state and return stats
        await self.update_tool_state(target_id, container_name)

        stats = {
            "endpoints_found": total_endpoints,
            "assets_saved": total_assets,
            "params_saved": total_params,
            "js_files_processed": len(js_files),
            "skipped_cooldown": False,
        }
        log.info("linkfinder complete", extra=stats)
        return stats
