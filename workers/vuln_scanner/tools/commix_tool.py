"""CommixTool -- OS command injection detection via commix."""

from __future__ import annotations

import os
import shutil
import tempfile
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("commix-tool")

COMMIX_TIMEOUT = int(os.environ.get("COMMIX_TIMEOUT", "300"))


class CommixTool(VulnScanTool):
    """OS command injection scanning via commix."""

    name = "commix"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_vuln_indicator(stdout: str) -> list[str]:
        """Extract vulnerability indicator lines from commix stdout."""
        findings: list[str] = []
        for line in stdout.splitlines():
            low = line.lower()
            if "is vulnerable" in low or "injectable" in low:
                findings.append(line.strip())
        return findings

    @staticmethod
    def _parse_output_dir(output_dir: str) -> list[str]:
        """Walk commix output directory for log files containing vuln indicators."""
        findings: list[str] = []
        for root, _dirs, files in os.walk(output_dir):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    with open(path) as fh:
                        for line in fh:
                            low = line.lower()
                            if "is vulnerable" in low or "injectable" in low:
                                findings.append(line.strip())
                except OSError:
                    pass
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
        triaged_findings = kwargs.get("triaged_findings")
        scan_all = kwargs.get("scan_all", False)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping commix -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Rate-limit delay from target profile
        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 0)
        delay = max(rate_limit / 1000.0, 0) if rate_limit else 0

        if triaged_findings:
            # -- Stage 2: confirm specific command injection findings --
            for vuln_id, asset_id, severity, title, poc in triaged_findings:
                target_url = poc or ""
                if not target_url.startswith("http"):
                    continue

                tmpdir = tempfile.mkdtemp(prefix="commix-")
                try:
                    cmd = [
                        "commix",
                        f"--url={target_url}",
                        "--batch",
                        f"--output-dir={tmpdir}",
                        "--technique=all",
                    ]
                    if delay > 0:
                        cmd.extend(["--delay", str(delay)])

                    async with sem:
                        try:
                            stdout = await self.run_subprocess(cmd, timeout=COMMIX_TIMEOUT)
                        except Exception as exc:
                            log.error("commix failed for %s: %s", target_url, exc)
                            continue

                    found_lines = self._is_vuln_indicator(stdout) + self._parse_output_dir(tmpdir)
                    if found_lines:
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        poc_text = "\n".join(found_lines[:5])
                        await self._update_vulnerability(
                            vuln_id=vuln_id,
                            severity=severity,
                            poc=f"commix confirmed:\n{poc_text}",
                            source_tool="commix",
                            description=f"commix confirmed command injection: {title}",
                        )
                        log.info("commix confirmed command injection at %s", target_url)
                finally:
                    shutil.rmtree(tmpdir, ignore_errors=True)

        elif scan_all:
            # -- Stage 3: broad command injection sweep --
            all_params = await self._get_all_parameters(target_id)

            # Group params by (asset_id, source_url)
            url_params: dict[tuple[int, str], list[tuple[str, str | None]]] = {}
            for asset_id, param_name, param_value, source_url in all_params:
                key = (asset_id, source_url or "")
                url_params.setdefault(key, []).append((param_name, param_value))

            for (asset_id, source_url), params in url_params.items():
                if not source_url or not source_url.startswith("http"):
                    continue

                if await self._has_confirmed_vuln(target_id, asset_id, "command injection"):
                    log.debug("Skipping %s -- already confirmed cmdi", source_url)
                    continue

                # Build URL with params
                parsed = urlparse(source_url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for name, value in params:
                    qs.setdefault(name, []).append(value or "1")
                scan_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                tmpdir = tempfile.mkdtemp(prefix="commix-")
                try:
                    cmd = [
                        "commix",
                        f"--url={scan_url}",
                        "--batch",
                        f"--output-dir={tmpdir}",
                        "--technique=all",
                    ]
                    if delay > 0:
                        cmd.extend(["--delay", str(delay)])

                    async with sem:
                        try:
                            stdout = await self.run_subprocess(cmd, timeout=COMMIX_TIMEOUT)
                        except Exception as exc:
                            log.error("commix failed for %s: %s", source_url, exc)
                            continue

                    found_lines = self._is_vuln_indicator(stdout) + self._parse_output_dir(tmpdir)
                    if found_lines:
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        poc_text = "\n".join(found_lines[:5])
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=f"OS Command Injection - {source_url}",
                            description=f"commix detected command injection at {source_url}",
                            poc=poc_text,
                        )
                        log.info("commix found command injection at %s", source_url)
                finally:
                    shutil.rmtree(tmpdir, ignore_errors=True)
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        await self.update_tool_state(target_id, container_name)
        log.info("commix complete", extra=stats)
        return stats
