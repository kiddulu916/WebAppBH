"""XXEinjectorTool -- XML External Entity injection detection via XXEinjector."""

from __future__ import annotations

import os

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("xxeinjector-tool")

XXE_TIMEOUT = int(os.environ.get("XXE_TIMEOUT", "300"))

XML_TECH_KEYWORDS = frozenset(["xml", "soap", "wsdl"])


class XXEinjectorTool(VulnScanTool):
    """XML External Entity injection scanning via XXEinjector."""

    name = "xxeinjector"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_xml_tech(tech_stack: dict | None) -> bool:
        """Return True if tech_stack suggests XML processing."""
        if not tech_stack:
            return False
        text = str(tech_stack).lower()
        return any(kw in text for kw in XML_TECH_KEYWORDS)

    @staticmethod
    def _is_xxe_indicator(stdout: str) -> bool:
        """Check if XXEinjector stdout signals a vulnerability."""
        for line in stdout.splitlines():
            low = line.lower()
            if "vulnerable" in low or "successfully" in low or "file retrieved" in low:
                return True
        return False

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
            log.info("Skipping xxeinjector -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        if triaged_findings:
            # -- Stage 2: confirm specific XXE findings --
            for vuln_id, asset_id, severity, title, poc in triaged_findings:
                target_url = poc or ""
                if not target_url.startswith("http"):
                    continue

                cmd = [
                    "ruby",
                    "/opt/XXEinjector/XXEinjector.rb",
                    f"--url={target_url}",
                    "--oob",
                ]

                async with sem:
                    try:
                        stdout = await self.run_subprocess(cmd, timeout=XXE_TIMEOUT)
                    except Exception as exc:
                        log.error(f"XXEinjector failed for {target_url}: {exc}")
                        continue

                if self._is_xxe_indicator(stdout):
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._update_vulnerability(
                        vuln_id=vuln_id,
                        severity=severity,
                        poc=f"XXEinjector confirmed:\n{stdout[:500]}",
                        source_tool="xxeinjector",
                        description=f"XXEinjector confirmed XXE vulnerability: {title}",
                    )
                    log.info(f"XXEinjector confirmed XXE at {target_url}")

        elif scan_all:
            # -- Stage 3: broad XXE sweep --
            all_url_assets = await self._get_all_url_assets(target_id)

            for asset_id, url in all_url_assets:
                if not url.startswith("http"):
                    continue

                # Only target URLs where tech stack suggests XML processing
                tech_stack = await self._get_tech_stack(asset_id)
                if not self._has_xml_tech(tech_stack):
                    continue

                if await self._has_confirmed_vuln(target_id, asset_id, "xxe"):
                    log.debug(f"Skipping {url} -- already confirmed XXE")
                    continue

                cmd = [
                    "ruby",
                    "/opt/XXEinjector/XXEinjector.rb",
                    f"--url={url}",
                    "--oob",
                ]

                async with sem:
                    try:
                        stdout = await self.run_subprocess(cmd, timeout=XXE_TIMEOUT)
                    except Exception as exc:
                        log.error(f"XXEinjector failed for {url}: {exc}")
                        continue

                if self._is_xxe_indicator(stdout):
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="high",
                        title=f"XML External Entity Injection - {url}",
                        description=f"XXEinjector detected XXE at {url}",
                        poc=stdout[:500],
                    )
                    log.info(f"XXEinjector found XXE at {url}")
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        await self.update_tool_state(target_id, container_name)
        log.info("xxeinjector complete", extra=stats)
        return stats
