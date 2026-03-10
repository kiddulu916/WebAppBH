"""TplmapTool -- Server-Side Template Injection detection via tplmap."""

from __future__ import annotations

import os
import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("tplmap-tool")

TPLMAP_TIMEOUT = int(os.environ.get("TPLMAP_TIMEOUT", "300"))

TEMPLATE_ENGINES = frozenset(
    ["jinja2", "twig", "freemarker", "mako", "pebble", "velocity", "smarty"]
)


class TplmapTool(VulnScanTool):
    """Server-Side Template Injection scanning via tplmap."""

    name = "tplmap"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_engine(tech_stack: dict | None) -> str | None:
        """Return the template engine name if detected in tech_stack."""
        if not tech_stack:
            return None
        if isinstance(tech_stack, dict):
            for key in tech_stack:
                if key.lower() in TEMPLATE_ENGINES:
                    return key.lower()
        elif isinstance(tech_stack, list):
            for item in tech_stack:
                name = item if isinstance(item, str) else (item.get("name", "") if isinstance(item, dict) else "")
                if name.lower() in TEMPLATE_ENGINES:
                    return name.lower()
        return None

    @staticmethod
    def _is_ssti_indicator(stdout: str) -> bool:
        """Check if tplmap stdout signals SSTI confirmation."""
        for line in stdout.splitlines():
            low = line.lower()
            if "confirmed" in low or "exploitable" in low or "identified" in low:
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
            log.info("Skipping tplmap -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Rate-limit delay from target profile
        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 0)
        delay = max(rate_limit / 1000.0, 0) if rate_limit else 0

        if triaged_findings:
            # -- Stage 2: confirm specific SSTI findings --
            for vuln_id, asset_id, severity, title, poc in triaged_findings:
                target_url = poc or ""
                if not target_url.startswith("http"):
                    continue

                cmd = ["tplmap", "-u", target_url]

                # If tech stack has engine info, add --engine flag
                tech_stack = await self._get_tech_stack(asset_id) if asset_id else None
                engine = self._detect_engine(tech_stack)
                if engine:
                    cmd.extend(["--engine", engine])
                if delay > 0:
                    cmd.extend(["--delay", str(delay)])

                async with sem:
                    try:
                        stdout = await self.run_subprocess(cmd, timeout=TPLMAP_TIMEOUT)
                    except Exception as exc:
                        log.error(f"tplmap failed for {target_url}: {exc}")
                        continue

                if self._is_ssti_indicator(stdout):
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._update_vulnerability(
                        vuln_id=vuln_id,
                        severity=severity,
                        poc=f"tplmap confirmed SSTI:\n{stdout[:500]}",
                        source_tool="tplmap",
                        description=f"tplmap confirmed Server-Side Template Injection: {title}",
                    )
                    log.info(f"tplmap confirmed SSTI at {target_url}")

        elif scan_all:
            # -- Stage 3: broad SSTI sweep --
            all_url_assets = await self._get_all_url_assets(target_id)

            for asset_id, url in all_url_assets:
                if not url.startswith("http"):
                    continue

                # Only scan if tech stack suggests a template engine
                tech_stack = await self._get_tech_stack(asset_id)
                engine = self._detect_engine(tech_stack)
                if not engine:
                    continue

                if await self._has_confirmed_vuln(target_id, asset_id, "template injection"):
                    log.debug(f"Skipping {url} -- already confirmed SSTI")
                    continue

                # Build URL with params if available
                params = await self._get_parameters_for_asset(asset_id)
                scan_url = url
                if params:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    for name, value, _src in params:
                        qs.setdefault(name, []).append(value or "1")
                    scan_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                cmd = ["tplmap", "-u", scan_url, "--engine", engine]
                if delay > 0:
                    cmd.extend(["--delay", str(delay)])

                async with sem:
                    try:
                        stdout = await self.run_subprocess(cmd, timeout=TPLMAP_TIMEOUT)
                    except Exception as exc:
                        log.error(f"tplmap failed for {url}: {exc}")
                        continue

                if self._is_ssti_indicator(stdout):
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="high",
                        title=f"Server-Side Template Injection ({engine}) - {url}",
                        description=f"tplmap detected SSTI via {engine} engine at {url}",
                        poc=stdout[:500],
                    )
                    log.info(f"tplmap found SSTI at {url} (engine={engine})")
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        await self.update_tool_state(target_id, container_name)
        log.info("tplmap complete", extra=stats)
        return stats
