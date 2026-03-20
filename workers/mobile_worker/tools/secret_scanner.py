"""SecretScannerTool -- Stage 2: regex-based secret extraction from decompiled source.

Scans Jadx output for AWS keys, Firebase URLs, Google API keys,
hardcoded passwords, private keys, and generic API tokens.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("secret-scanner")

# Regex patterns keyed by secret type
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "firebase_url": re.compile(r"https?://[\w.-]+\.firebaseio\.com"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "private_key": re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----"),
    "hardcoded_password": re.compile(
        r"""(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']""", re.IGNORECASE
    ),
    "generic_api_key": re.compile(
        r"""(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*["'][^"']{8,}["']""",
        re.IGNORECASE,
    ),
}

CRITICAL_TYPES = {"aws_key", "private_key"}


class SecretScannerTool(MobileTestTool):
    """Scan decompiled Java source for hardcoded secrets."""

    name = "secret_scanner"
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
            log.info("Skipping secret_scanner -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        # Scan all jadx output directories
        for jadx_dir in analysis_dir.glob("*_jadx"):
            for java_file in jadx_dir.rglob("*.java"):
                try:
                    text = java_file.read_text(errors="replace")
                    findings = self._scan_text(text)
                    for finding in findings:
                        severity = self._severity_for(finding["type"])
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=None,
                            severity=severity,
                            title=f"Hardcoded {finding['type']}: {finding['value'][:40]}",
                            description=(
                                f"Found {finding['type']} in {java_file.name}: "
                                f"{finding['value'][:80]}"
                            ),
                        )
                        stats["found"] += 1
                        stats["new"] += 1
                except Exception as exc:
                    log.error(f"Error scanning {java_file}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("secret_scanner complete", extra=stats)
        return stats

    @staticmethod
    def _scan_text(text: str) -> list[dict]:
        """Run all regex patterns against text. Returns list of findings."""
        findings: list[dict] = []
        seen: set[str] = set()
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                if value not in seen:
                    seen.add(value)
                    findings.append({"type": secret_type, "value": value})
        return findings

    @staticmethod
    def _severity_for(secret_type: str) -> str:
        """Map secret type to severity level."""
        return "critical" if secret_type in CRITICAL_TYPES else "high"
