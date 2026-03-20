"""MobsfSecretsTool -- Stage 2: parse MobSF report for secrets.

Extracts MobSF's own secret findings from the cached JSON report
and deduplicates against SecretScanner results by secret value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("mobsf-secrets")

# Pattern to extract secret values from MobSF descriptions
SECRET_VALUE_RE = re.compile(r"[A-Za-z0-9_/+=]{8,}")


class MobsfSecretsTool(MobileTestTool):
    """Parse MobSF report for secrets, deduplicate against regex scanner."""

    name = "mobsf_secrets"
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
            log.info("Skipping mobsf_secrets -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        # Collect existing secret values from prior scanner vulns for dedup
        existing_values = await self._get_existing_secret_values(target_id)

        for report_file in analysis_dir.glob("*_mobsf.json"):
            try:
                with open(report_file) as f:
                    report = json.load(f)

                findings = self._extract_secrets(report)
                deduped = self._deduplicate(findings, existing_values)

                for finding in deduped:
                    severity = self._map_severity(finding.get("severity", "warning"))
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=None,
                        severity=severity,
                        title=f"MobSF: {finding['title']}",
                        description=finding["description"],
                    )
                    stats["found"] += 1
                    stats["new"] += 1

            except Exception as exc:
                log.error(f"Error parsing MobSF report {report_file}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("mobsf_secrets complete", extra=stats)
        return stats

    @staticmethod
    def _extract_secrets(report: dict) -> list[dict]:
        """Extract secret findings from MobSF report JSON."""
        findings: list[dict] = []
        for entry in report.get("secrets", []):
            findings.append({
                "title": entry.get("title", "Unknown Secret"),
                "description": entry.get("description", ""),
                "severity": entry.get("severity", "warning"),
            })
        return findings

    @staticmethod
    def _deduplicate(
        mobsf_findings: list[dict], existing_values: set[str]
    ) -> list[dict]:
        """Remove findings whose secret value already exists."""
        deduped: list[dict] = []
        for finding in mobsf_findings:
            desc = finding.get("description", "")
            # Check if any known secret value appears in this finding
            is_dup = any(val in desc for val in existing_values if val)
            if not is_dup:
                deduped.append(finding)
        return deduped

    @staticmethod
    def _map_severity(mobsf_severity: str) -> str:
        """Map MobSF severity labels to our severity levels."""
        mapping = {
            "high": "high",
            "warning": "medium",
            "info": "info",
            "good": "info",
        }
        return mapping.get(mobsf_severity.lower(), "medium")

    async def _get_existing_secret_values(self, target_id: int) -> set[str]:
        """Collect secret values from existing vulnerabilities for dedup."""
        from sqlalchemy import select
        from lib_webbh import Vulnerability, get_session

        values: set[str] = set()
        async with get_session() as session:
            stmt = select(Vulnerability.title).where(
                Vulnerability.target_id == target_id,
                Vulnerability.source_tool == "secret_scanner",
            )
            result = await session.execute(stmt)
            for row in result.scalars().all():
                # Extract the secret value from title like "Hardcoded aws_key: AKIA..."
                parts = row.split(": ", 1)
                if len(parts) == 2:
                    values.add(parts[1].strip())
        return values
