"""Mantra -- Stage 2 secret detection in saved JS files.

Reads saved JS files from disk and runs the ``mantra`` CLI tool
against each to detect secrets and sensitive data.  Discovered secrets
are persisted as Vulnerability rows with critical severity.
"""

from __future__ import annotations

import glob
import json
import os

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("mantra")

# Base directory for raw JS file storage.  Tests patch this to tmp_path.
JS_DIR = "/app/shared/raw"


class Mantra(WebAppTool):
    """Detect secrets in saved JS files using Mantra CLI."""

    name = "mantra"
    tool_type = ToolType.CLI
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_output(stdout: str) -> list[dict]:
        """Parse mantra JSON-per-line output.

        Each line is expected to be a JSON object with ``type``, ``match``,
        and ``file`` keys.  Lines that fail to parse are silently skipped.
        """
        results: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    results.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue
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
        """Run Mantra against all saved JS files for *target_id*.

        Returns a stats dict with keys: secrets_found, vulns_saved,
        js_files_processed, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="secret")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping mantra -- within cooldown period")
            return {
                "secrets_found": 0,
                "vulns_saved": 0,
                "js_files_processed": 0,
                "skipped_cooldown": True,
            }

        # 2. Glob JS files from disk
        js_dir = os.path.join(JS_DIR, str(target_id), "js")
        js_files = glob.glob(os.path.join(js_dir, "*.js"))
        if not js_files:
            log.info("No JS files found -- nothing to analyse")
            return {
                "secrets_found": 0,
                "vulns_saved": 0,
                "js_files_processed": 0,
                "skipped_cooldown": False,
            }

        total_secrets = 0
        total_vulns = 0

        # 3. Run mantra against each JS file
        for filepath in js_files:
            try:
                stdout = await self.run_subprocess(
                    ["mantra", "-f", filepath],
                    timeout=60,
                )
            except Exception as exc:
                log.warning(f"mantra failed on {filepath}: {exc}")
                continue

            secrets = self.parse_output(stdout)
            total_secrets += len(secrets)

            # 4. Save each secret as a vulnerability
            filename = os.path.basename(filepath)
            for secret in secrets:
                secret_type = secret.get("type", "unknown")
                match = secret.get("match", "")
                await self._save_vulnerability(
                    target_id=target_id,
                    asset_id=None,
                    severity="critical",
                    title=f"{secret_type} found in {filename}",
                    description=f"Secret type: {secret_type}",
                    poc=match[:500],
                )
                total_vulns += 1

        # 5. Update tool state and return stats
        await self.update_tool_state(target_id, container_name)

        stats = {
            "secrets_found": total_secrets,
            "vulns_saved": total_vulns,
            "js_files_processed": len(js_files),
            "skipped_cooldown": False,
        }
        log.info("mantra complete", extra=stats)
        return stats
