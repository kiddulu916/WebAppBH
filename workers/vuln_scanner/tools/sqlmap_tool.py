"""SqlmapTool -- SQL injection detection and confirmation via sqlmap."""

from __future__ import annotations

import os
import re
import tempfile
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("sqlmap-tool")

SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", "300"))
SQLMAP_THREADS = int(os.environ.get("SQLMAP_THREADS", "1"))


class SqlmapTool(VulnScanTool):
    """SQL injection scanning via sqlmap."""

    name = "sqlmap"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_to_risk_level(severity: str) -> tuple[int, int]:
        """Map Nuclei severity to sqlmap --risk and --level values."""
        sev = severity.lower()
        if sev in ("critical", "high"):
            return 3, 5
        return 2, 3

    @staticmethod
    def _parse_log_dir(output_dir: str) -> list[str]:
        """Walk the sqlmap output directory for log files and extract vuln lines."""
        findings: list[str] = []
        for root, _dirs, files in os.walk(output_dir):
            for fname in files:
                if fname == "log":
                    path = os.path.join(root, fname)
                    try:
                        with open(path) as fh:
                            for line in fh:
                                if "is vulnerable" in line.lower() or "injectable" in line.lower():
                                    findings.append(line.strip())
                    except OSError:
                        pass
        return findings

    @staticmethod
    def _parse_stdout(stdout: str) -> list[str]:
        """Extract vulnerability indicators from sqlmap stdout."""
        findings: list[str] = []
        for line in stdout.splitlines():
            low = line.lower()
            if "is vulnerable" in low or "injectable" in low:
                findings.append(line.strip())
        return findings

    @staticmethod
    def _build_url_with_params(
        base_url: str,
        params: list[tuple[str, str | None]],
    ) -> str:
        """Append query params to a URL."""
        parsed = urlparse(base_url)
        existing = parse_qs(parsed.query, keep_blank_values=True)
        for name, value in params:
            existing.setdefault(name, []).append(value or "1")
        new_query = urlencode(existing, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

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
        triaged_findings = kwargs.get("triaged_findings")
        scan_all = kwargs.get("scan_all", False)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping sqlmap -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Rate-limit delay from target profile
        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 0)
        delay = max(rate_limit / 1000.0, 0) if rate_limit else 0

        if triaged_findings:
            # -- Stage 2: confirm specific Nuclei SQLi findings --
            for vuln_id, asset_id, severity, title, poc in triaged_findings:
                target_url = poc or ""
                if not target_url.startswith("http"):
                    continue

                risk, level = self._severity_to_risk_level(severity)
                tmpdir = tempfile.mkdtemp(prefix="sqlmap-")
                try:
                    cmd = [
                        "sqlmap",
                        "-u", target_url,
                        "--batch",
                        "--random-agent",
                        "--output-dir", tmpdir,
                        "--forms",
                        f"--risk={risk}",
                        f"--level={level}",
                        "--tamper=between,randomcase",
                        f"--threads={SQLMAP_THREADS}",
                    ]
                    if delay > 0:
                        cmd.extend(["--delay", str(delay)])

                    async with sem:
                        try:
                            stdout = await self.run_subprocess(cmd, timeout=SQLMAP_TIMEOUT)
                        except Exception as exc:
                            log.error("sqlmap failed for %s: %s", target_url, exc)
                            continue

                    found_lines = self._parse_log_dir(tmpdir) + self._parse_stdout(stdout)
                    if found_lines:
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        poc_text = "\n".join(found_lines[:5])
                        await self._update_vulnerability(
                            vuln_id=vuln_id,
                            severity=severity,
                            poc=f"sqlmap confirmed:\n{poc_text}",
                            source_tool="sqlmap",
                            description=f"sqlmap confirmed SQL injection: {title}",
                        )
                        log.info("sqlmap confirmed SQLi at %s", target_url)
                finally:
                    _cleanup_dir(tmpdir)

        elif scan_all:
            # -- Stage 3: broad SQLi sweep --
            all_params = await self._get_all_parameters(target_id)

            # Group params by (asset_id, source_url)
            url_params: dict[tuple[int, str], list[tuple[str, str | None]]] = {}
            for asset_id, param_name, param_value, source_url in all_params:
                key = (asset_id, source_url or "")
                url_params.setdefault(key, []).append((param_name, param_value))

            for (asset_id, source_url), params in url_params.items():
                if not source_url or not source_url.startswith("http"):
                    continue

                if await self._has_confirmed_vuln(target_id, asset_id, "sql injection"):
                    log.debug("Skipping %s -- already confirmed SQLi", source_url)
                    continue

                scan_url = self._build_url_with_params(source_url, params)
                tmpdir = tempfile.mkdtemp(prefix="sqlmap-")
                try:
                    cmd = [
                        "sqlmap",
                        "-u", scan_url,
                        "--batch",
                        "--random-agent",
                        "--output-dir", tmpdir,
                        "--forms",
                        "--risk=2",
                        "--level=3",
                        "--crawl=1",
                        f"--threads={SQLMAP_THREADS}",
                    ]
                    if delay > 0:
                        cmd.extend(["--delay", str(delay)])

                    async with sem:
                        try:
                            stdout = await self.run_subprocess(cmd, timeout=SQLMAP_TIMEOUT)
                        except Exception as exc:
                            log.error("sqlmap failed for %s: %s", source_url, exc)
                            continue

                    found_lines = self._parse_log_dir(tmpdir) + self._parse_stdout(stdout)
                    if found_lines:
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        poc_text = "\n".join(found_lines[:5])
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=f"SQL Injection - {source_url}",
                            description=f"sqlmap detected SQL injection at {source_url}",
                            poc=poc_text,
                        )
                        log.info("sqlmap found SQLi at %s", source_url)
                finally:
                    _cleanup_dir(tmpdir)
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        await self.update_tool_state(target_id, container_name)
        log.info("sqlmap complete", extra=stats)
        return stats


def _cleanup_dir(path: str) -> None:
    """Best-effort recursive removal of a temp directory."""
    import shutil

    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
