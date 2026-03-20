"""IosPlistAuditorTool -- Stage 3: audit iOS plist/ATS from MobSF report.

Checks: NSAllowsArbitraryLoads, missing ATS dictionary,
insecure URL schemes, broad entitlements.
"""

from __future__ import annotations

import json
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("ios-plist-auditor")


class IosPlistAuditorTool(MobileTestTool):
    """Audit iOS plist fields from MobSF report."""

    name = "ios_plist_auditor"
    weight_class = WeightClass.STATIC

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
            log.info("Skipping ios_plist_auditor -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        for report_file in analysis_dir.glob("*_mobsf.json"):
            try:
                with open(report_file) as f:
                    report = json.load(f)

                # Only process iOS reports
                if report.get("file_name", "").endswith(".ipa") or \
                   report.get("platform", "") == "ios":
                    findings = self._audit_plist(report)
                    for finding in findings:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=None,
                            severity=finding["severity"],
                            title=finding["title"],
                            description=finding["description"],
                        )
                        stats["found"] += 1
                        stats["new"] += 1

            except Exception as exc:
                log.error(f"Error auditing plist from {report_file}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("ios_plist_auditor complete", extra=stats)
        return stats

    @staticmethod
    def _audit_plist(report: dict) -> list[dict]:
        """Audit iOS plist data from MobSF report. Returns list of findings."""
        findings: list[dict] = []

        # ATS checks
        ats = report.get("app_transport_security", {})
        if isinstance(ats, dict):
            if ats.get("NSAllowsArbitraryLoads") is True:
                findings.append({
                    "title": "NSAllowsArbitraryLoads enabled",
                    "severity": "high",
                    "description": (
                        "App Transport Security is disabled — the app allows "
                        "arbitrary plaintext HTTP connections."
                    ),
                })
        elif ats is None or (isinstance(ats, dict) and not ats):
            findings.append({
                "title": "Missing App Transport Security configuration",
                "severity": "medium",
                "description": "No NSAppTransportSecurity dictionary found in Info.plist.",
            })

        # URL schemes
        url_schemes = report.get("url_schemes", [])
        if isinstance(url_schemes, list) and url_schemes:
            for scheme in url_schemes:
                findings.append({
                    "title": f"Insecure URL scheme registered: {scheme}",
                    "severity": "medium",
                    "description": (
                        f"Custom URL scheme '{scheme}' in CFBundleURLTypes — "
                        f"may accept arbitrary data without validation."
                    ),
                })

        # Broad entitlements
        entitlements = report.get("entitlements", {})
        if isinstance(entitlements, dict):
            domains = entitlements.get("com.apple.developer.associated-domains", [])
            if isinstance(domains, list):
                for domain in domains:
                    if "*" in str(domain):
                        findings.append({
                            "title": f"Wildcard associated domain: {domain}",
                            "severity": "medium",
                            "description": (
                                f"Broad wildcard in associated-domains entitlement: {domain}"
                            ),
                        })

        return findings
