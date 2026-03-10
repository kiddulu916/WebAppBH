"""SmugglerTool -- HTTP request smuggling detection via smuggler."""

from __future__ import annotations

import os

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("smuggler-tool")

SMUGGLER_TIMEOUT = int(os.environ.get("SMUGGLER_TIMEOUT", "180"))


class SmugglerTool(VulnScanTool):
    """HTTP request smuggling detection via smuggler."""

    name = "smuggler"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_smuggling_indicator(stdout: str) -> list[str]:
        """Extract smuggling indicator lines from stdout."""
        findings: list[str] = []
        for line in stdout.splitlines():
            low = line.lower()
            if "vulnerable" in low or "cl.te" in low or "te.cl" in low or "te.te" in low:
                findings.append(line.strip())
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
            log.info("Skipping smuggler -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Collect URLs to test
        urls_to_test: list[tuple[int | None, str]] = []

        if triaged_findings:
            # -- Stage 2: test URLs from triaged findings --
            for vuln_id, asset_id, severity, title, poc in triaged_findings:
                target_url = poc or ""
                if target_url.startswith("http"):
                    urls_to_test.append((asset_id, target_url))

        elif scan_all:
            # -- Stage 3: test all live URLs --
            live_urls = await self._get_live_urls(target_id)
            for asset_id, domain in live_urls:
                url = f"https://{domain}"
                if await self._has_confirmed_vuln(target_id, asset_id, "request smuggling"):
                    log.debug("Skipping %s -- already confirmed smuggling", url)
                    continue
                urls_to_test.append((asset_id, url))
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        for asset_id, url in urls_to_test:
            cmd = [
                "python3", "/opt/smuggler/smuggler.py",
                "-u", url,
                "-q",
            ]

            async with sem:
                try:
                    stdout = await self.run_subprocess(cmd, timeout=SMUGGLER_TIMEOUT)
                except Exception as exc:
                    log.error("smuggler failed for %s: %s", url, exc)
                    continue

            found_lines = self._is_smuggling_indicator(stdout)
            if found_lines:
                stats["found"] += 1
                stats["in_scope"] += 1
                stats["new"] += 1
                poc_text = "\n".join(found_lines[:5])

                if triaged_findings:
                    # Find the matching triaged finding to update
                    for vuln_id, _aid, severity, title, _poc in triaged_findings:
                        if _aid == asset_id:
                            await self._update_vulnerability(
                                vuln_id=vuln_id,
                                severity=severity,
                                poc=f"smuggler confirmed:\n{poc_text}",
                                source_tool="smuggler",
                                description=f"smuggler confirmed HTTP request smuggling: {title}",
                            )
                            break
                else:
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="high",
                        title=f"HTTP Request Smuggling - {url}",
                        description=f"smuggler detected request smuggling at {url}",
                        poc=poc_text,
                    )
                log.info("smuggler found request smuggling at %s", url)

        await self.update_tool_state(target_id, container_name)
        log.info("smuggler complete", extra=stats)
        return stats
