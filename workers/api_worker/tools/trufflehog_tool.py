"""TrufflehogTool -- Stage 1 secret scanning of downloaded API specs.

Runs TruffleHog against API specification files saved to /tmp/api-specs/
by OpenapiParserTool.  Verified findings are saved as critical-severity
vulnerabilities; unverified findings as medium.
"""

from __future__ import annotations

import json
import os

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass

logger = setup_logger("trufflehog-tool")


class TrufflehogTool(ApiTestTool):
    """Scan downloaded API specs for leaked secrets with TruffleHog."""

    name = "trufflehog"
    weight_class = WeightClass.LIGHT

    SPECS_DIR = "/tmp/api-specs"

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> list[dict]:
        """Parse trufflehog JSON-lines output.

        Returns::

            [{"detector": "AWS", "raw": "AKIA...",
              "verified": True, "file": "..."}]
        """
        findings: list[dict] = []
        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                finding: dict = {
                    "detector": data.get("DetectorName", "Unknown"),
                    "raw": data.get("Raw", ""),
                    "verified": data.get("Verified", False),
                    "file": "",
                }
                source_meta = data.get("SourceMetadata", {}).get("Data", {})
                fs = source_meta.get("Filesystem", {})
                finding["file"] = fs.get("file", "")
                findings.append(finding)
            except json.JSONDecodeError:
                continue
        return findings

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
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping trufflehog -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # Check if spec files exist (populated by OpenapiParserTool)
        if not os.path.isdir(self.SPECS_DIR):
            log.info("No api-specs directory found — skipping trufflehog")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        spec_files = os.listdir(self.SPECS_DIR)
        if not spec_files:
            log.info("No spec files found — skipping trufflehog")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        cmd = [
            "trufflehog",
            "filesystem",
            self.SPECS_DIR,
            "--json",
            "--no-update",
        ]

        try:
            raw = await self.run_subprocess(cmd)
        except Exception as exc:
            log.error(f"trufflehog failed: {exc}")
            return stats

        findings = self.parse_output(raw)
        stats["found"] = len(findings)

        # We need an asset_id for saving vulns — grab first live URL
        urls = await self._get_live_urls(target_id)
        default_asset_id = urls[0][0] if urls else None

        for finding in findings:
            if default_asset_id is None:
                log.warning(
                    "No asset to associate trufflehog finding with — skipping"
                )
                break

            severity = "critical" if finding["verified"] else "medium"
            detector = finding["detector"]
            raw_secret = finding["raw"]
            file_path = finding["file"]

            # Mask the raw secret for safe storage
            masked = raw_secret[:6] + "..." if len(raw_secret) > 6 else "***"

            await self._save_vulnerability(
                target_id=target_id,
                asset_id=default_asset_id,
                severity=severity,
                title=(
                    f"{'Verified' if finding['verified'] else 'Potential'} "
                    f"secret ({detector}) in API spec"
                ),
                description=(
                    f"TruffleHog detected a {detector} secret in {file_path}. "
                    f"Raw (masked): {masked}. "
                    f"Verified: {finding['verified']}."
                ),
                poc=f"File: {file_path}, Detector: {detector}",
            )
            stats["in_scope"] += 1
            stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("trufflehog complete", extra=stats)
        return stats
