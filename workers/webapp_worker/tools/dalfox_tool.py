"""DalfoxTool -- XSS scanning via dalfox CLI.

Runs the dalfox XSS scanner against live URLs discovered for the target.
Parses JSON output to extract verified and potential XSS vulnerabilities,
saving each finding as a Vulnerability with appropriate severity.
"""

from __future__ import annotations

import json
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("dalfox")

# Default request delay in milliseconds between dalfox requests.
DALFOX_DELAY_MS = int(os.environ.get("DALFOX_DELAY_MS", "100"))

# Maximum concurrent dalfox workers per URL scan.
DALFOX_WORKERS = int(os.environ.get("DALFOX_WORKERS", "5"))


class DalfoxTool(WebAppTool):
    """Scan live URLs for XSS vulnerabilities using dalfox."""

    name = "dalfox"
    tool_type = ToolType.CLI
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_output(filepath: str) -> list[dict]:
        """Parse dalfox JSON output file (one JSON object per line).

        Returns a list of finding dicts with keys: type, param, payload,
        poc, evidence, severity.
        """
        findings: list[dict] = []
        if not os.path.isfile(filepath):
            return findings

        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                finding_type = obj.get("type", "").lower()
                # dalfox marks verified XSS as "verified" type
                is_verified = "verified" in finding_type or "vuln" in finding_type

                findings.append({
                    "type": obj.get("type", "unknown"),
                    "param": obj.get("param", ""),
                    "payload": obj.get("payload", ""),
                    "poc": obj.get("poc", obj.get("data", "")),
                    "evidence": obj.get("evidence", obj.get("message", "")),
                    "severity": "high" if is_verified else "medium",
                })

        return findings

    # ------------------------------------------------------------------
    # Command builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_cmd(
        url: str,
        output_path: str,
        headers: dict | None = None,
    ) -> list[str]:
        """Build the dalfox CLI command list."""
        cmd = [
            "dalfox", "url", url,
            "--silence",
            "--no-color",
            "--format", "json",
            "--output", output_path,
            "--delay", str(DALFOX_DELAY_MS),
            "--worker", str(DALFOX_WORKERS),
        ]

        if headers:
            for key, value in headers.items():
                cmd.extend(["--header", f"{key}: {value}"])

        return cmd

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
        """Run dalfox against live URLs for *target_id*.

        Returns a stats dict with keys: found, in_scope, new,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="xss")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping dalfox -- within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # 2. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found -- nothing to scan")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        total_found = 0
        total_in_scope = 0
        total_new = 0

        sem = get_semaphore(self.weight_class)

        # 3. Scan each URL
        for asset_id, domain in urls:
            async with sem:
                scan_url = f"https://{domain}"
                tmp_fd, tmp_path = tempfile.mkstemp(
                    prefix="dalfox_", suffix=".json"
                )
                os.close(tmp_fd)

                try:
                    cmd = self._build_cmd(scan_url, tmp_path, headers)
                    log.info(
                        f"Running dalfox against {domain}",
                        extra={"domain": domain},
                    )
                    await self.run_subprocess(cmd)

                    # 4. Parse results
                    findings = self.parse_output(tmp_path)
                    total_found += len(findings)

                    # 5. Save each finding
                    for finding in findings:
                        total_in_scope += 1

                        poc_text = finding["poc"] or finding["payload"]
                        description = (
                            f"XSS vulnerability detected on {domain}.\n\n"
                            f"Type: {finding['type']}\n"
                            f"Parameter: {finding['param']}\n"
                            f"Payload: {finding['payload']}\n"
                        )
                        if finding["evidence"]:
                            description += f"Evidence: {finding['evidence']}\n"

                        vuln_id = await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity=finding["severity"],
                            title=(
                                f"XSS ({finding['type']}) via "
                                f"'{finding['param']}' on {domain}"
                            ),
                            description=description,
                            poc=poc_text,
                        )
                        if vuln_id:
                            total_new += 1

                except Exception as exc:
                    log.warning(
                        f"dalfox failed on {domain}: {exc}",
                        extra={"domain": domain},
                    )
                finally:
                    # 6. Cleanup temp file
                    if os.path.isfile(tmp_path):
                        os.unlink(tmp_path)

        # 7. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "found": total_found,
            "in_scope": total_in_scope,
            "new": total_new,
            "skipped_cooldown": False,
        }
        log.info("dalfox complete", extra=stats)
        return stats
