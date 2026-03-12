"""CorsScannerTool -- Stage 2 CORS misconfiguration scanner.

Wraps CORScanner CLI to detect overly permissive CORS configurations
such as reflected origins, null origin, and wildcard with credentials.
"""

from __future__ import annotations

import json
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("cors-scanner")


class CorsScannerTool(ApiTestTool):
    """Scan API endpoints for CORS misconfigurations using CORScanner."""

    name = "cors_scanner"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> list[dict]:
        """Parse CORScanner JSON output.

        Returns ``data.get("results", [])`` -- each dict has:
        url, type, origin, credentials.
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        return data.get("results", [])

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
            log.info("Skipping cors_scanner -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        urls = await self._get_api_urls(target_id)
        if not urls:
            log.info("No API URLs found for CORS scanning")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        sem = get_semaphore(self.weight_class)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Write all URLs to a temp file for batch scanning
        url_list: list[str] = []
        asset_map: dict[str, int] = {}
        for asset_id, url_val in urls:
            full_url = url_val if url_val.startswith("http") else f"https://{url_val}"
            url_list.append(full_url)
            asset_map[full_url] = asset_id

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp_in:
            tmp_in.write("\n".join(url_list))
            input_file = tmp_in.name

        output_file = "/tmp/cors-out.json"

        cmd = [
            "python3", "/opt/CORScanner/cors_scan.py",
            "-i", input_file,
            "-o", output_file,
        ]

        await sem.acquire()
        try:
            try:
                await self.run_subprocess(cmd)
            except Exception as exc:
                log.error(f"CORScanner failed: {exc}")
                return stats
            finally:
                raw = ""
                if os.path.exists(output_file):
                    with open(output_file) as fh:
                        raw = fh.read()
                    os.unlink(output_file)
                if os.path.exists(input_file):
                    os.unlink(input_file)
        finally:
            sem.release()

        findings = self.parse_output(raw)
        stats["found"] += len(findings)

        for finding in findings:
            vuln_url = finding.get("url", "")
            misconfig_type = finding.get("type", "unknown")
            origin = finding.get("origin", "")
            credentials = finding.get("credentials", False)

            # Determine severity: high if credentials=True, medium otherwise
            severity = "high" if credentials else "medium"

            # Look up asset_id from our map
            asset_id = asset_map.get(vuln_url)
            if asset_id is None:
                # Try matching without trailing slash
                for mapped_url, mapped_id in asset_map.items():
                    if vuln_url.rstrip("/") == mapped_url.rstrip("/"):
                        asset_id = mapped_id
                        break
            if asset_id is None:
                continue

            stats["in_scope"] += 1
            stats["new"] += 1

            creds_note = " (with credentials)" if credentials else ""
            await self._save_vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity=severity,
                title=f"CORS misconfiguration: {misconfig_type}{creds_note}",
                description=(
                    f"CORS misconfiguration at {vuln_url}: type={misconfig_type}, "
                    f"origin={origin}, credentials={credentials}"
                ),
                poc=f"Origin: {origin} -> {vuln_url}",
            )

        await self.update_tool_state(target_id, container_name)
        log.info("cors_scanner complete", extra=stats)
        return stats
