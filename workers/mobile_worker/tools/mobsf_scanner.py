"""MobsfScannerTool -- Stage 1: submit binary to MobSF REST API.

Uploads APK/IPA to MobSF sidecar, polls scan, fetches JSON report.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("mobsf-scanner")

MOBSF_URL = os.environ.get("MOBSF_URL", "http://mobsf:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")


class MobsfScannerTool(MobileTestTool):
    """Upload binaries to MobSF, poll scan, fetch report."""

    name = "mobsf_scanner"
    weight_class = WeightClass.STATIC

    SCAN_TIMEOUT = 600  # 10 minutes

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping mobsf_scanner -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        import httpx
        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        if not analysis_dir.is_dir():
            return stats

        binaries = list(analysis_dir.glob("*.apk")) + list(analysis_dir.glob("*.ipa"))

        for binary_path in binaries:
            try:
                platform = "android" if binary_path.suffix == ".apk" else "ios"

                async with httpx.AsyncClient(timeout=self.SCAN_TIMEOUT) as client:
                    headers = {"Authorization": MOBSF_API_KEY}

                    # Upload
                    with open(binary_path, "rb") as f:
                        upload_resp = await client.post(
                            f"{MOBSF_URL}/api/v1/upload",
                            headers=headers,
                            files={"file": (binary_path.name, f)},
                        )
                    upload_resp.raise_for_status()
                    upload_data = upload_resp.json()
                    scan_hash = upload_data.get("hash", "")

                    # Scan
                    scan_resp = await client.post(
                        f"{MOBSF_URL}/api/v1/scan",
                        headers=headers,
                        data={"hash": scan_hash},
                    )
                    scan_resp.raise_for_status()

                    # Report
                    report_resp = await client.post(
                        f"{MOBSF_URL}/api/v1/report_json",
                        headers=headers,
                        data={"hash": scan_hash},
                    )
                    report_resp.raise_for_status()
                    report = report_resp.json()

                # Extract score and package name
                package_name = report.get("package_name",
                                          report.get("app_name", binary_path.stem))
                score = report.get("security_score", report.get("average_cvss"))

                # Cache report
                cache_path = self._report_cache_path(target_id, package_name)
                Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
                with open(cache_path, "w") as f:
                    json.dump(report, f)

                # Save to DB
                score_float = float(score) if score is not None else None
                await self._save_mobile_app(
                    target_id=target_id,
                    platform=platform,
                    package_name=package_name,
                    mobsf_score=score_float,
                    source_tool=self.name,
                )

                stats["found"] += 1
                stats["new"] += 1
                log.info(f"MobSF scan complete: {package_name} (score={score})")

            except Exception as exc:
                log.error(f"MobSF scan failed for {binary_path.name}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("mobsf_scanner complete", extra=stats)
        return stats

    @staticmethod
    def _report_cache_path(target_id: int, package_name: str) -> str:
        """Generate the cache path for a MobSF JSON report."""
        return str(
            Path(MOBILE_ANALYSIS_DIR) / str(target_id)
            / f"{package_name}_mobsf.json"
        )
