"""ServiceWorkerAuditor — Stage 3 browser-based service worker audit.

Detects registered service workers via the browser API, probes common SW
file paths via HTTP, and checks SW source code for risky patterns such as
importScripts, cache.addAll, and no-cors fetch calls.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("service-worker-auditor")

# Common service-worker file paths to probe.
SW_PATHS: list[str] = [
    "/sw.js",
    "/service-worker.js",
    "/serviceworker.js",
    "/worker.js",
]

# Risky patterns to detect in SW source code.
SW_RISKY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"importScripts\s*\("), "importScripts usage"),
    (re.compile(r"\.addAll\s*\("), "cache.addAll usage"),
    (re.compile(r"fetch\s*\(.*\bmode\s*:\s*['\"]no-cors['\"]"), "no-cors fetch"),
]

# JavaScript snippet evaluated in page context to list registered SWs.
SW_REGISTRATIONS_EXPR = """() => {
    if (!navigator.serviceWorker) return [];
    return navigator.serviceWorker.getRegistrations().then(regs =>
        regs.map(r => ({
            scriptURL: r.active ? r.active.scriptURL : (r.installing ? r.installing.scriptURL : ''),
            scope: r.scope,
        }))
    );
}"""


class ServiceWorkerAuditor(WebAppTool):
    """Audit service worker registrations and source code for risky patterns."""

    name = "service_worker_auditor"
    tool_type = ToolType.BROWSER
    weight_class = WeightClass.HEAVY

    @staticmethod
    def _check_risky_patterns(source: str) -> list[str]:
        """Return descriptions of risky patterns found in *source*."""
        found: list[str] = []
        for pattern, description in SW_RISKY_PATTERNS:
            if pattern.search(source):
                found.append(description)
        return found

    @staticmethod
    def _is_same_origin(script_url: str, page_origin: str) -> bool:
        """Return True if *script_url* shares origin with *page_origin*."""
        try:
            parsed = urlparse(script_url)
            return parsed.scheme + "://" + parsed.netloc == page_origin
        except Exception:
            return False

    @staticmethod
    def _is_broad_scope(scope: str) -> bool:
        """Return True if the SW scope covers the entire origin (``/``)."""
        try:
            parsed = urlparse(scope)
            return parsed.path in ("/", "")
        except Exception:
            return False

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Audit service workers on live URLs.

        Returns a stats dict with keys: workers_found, risky_patterns,
        urls_checked, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="service_worker")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping service_worker_auditor — within cooldown period")
            return {
                "workers_found": 0,
                "risky_patterns": 0,
                "urls_checked": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning("No BrowserManager provided — skipping service_worker_auditor")
            return {
                "workers_found": 0,
                "risky_patterns": 0,
                "urls_checked": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found — nothing to check")
            return {
                "workers_found": 0,
                "risky_patterns": 0,
                "urls_checked": 0,
                "skipped_cooldown": False,
            }

        # httpx client for probing SW paths
        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=True,
            )
            should_close = True

        urls_checked = 0
        workers_found = 0
        risky_patterns = 0

        try:
            for asset_id, domain in urls:
                page = None
                try:
                    page_origin = f"https://{domain}"
                    page = await browser_mgr.new_page(headers=headers)
                    await page.goto(page_origin, wait_until="networkidle")
                    urls_checked += 1

                    # -------------------------------------------------
                    # Phase 1: Check navigator.serviceWorker registrations
                    # -------------------------------------------------
                    registrations = await page.evaluate(SW_REGISTRATIONS_EXPR)
                    if registrations is None:
                        registrations = []

                    for reg in registrations:
                        script_url = reg.get("scriptURL", "")
                        scope = reg.get("scope", "")
                        workers_found += 1

                        details: list[str] = []
                        severity = "info"

                        if not self._is_same_origin(script_url, page_origin):
                            details.append("cross-origin SW script")
                            severity = "medium"

                        if self._is_broad_scope(scope):
                            details.append("overly broad scope (/)")
                            severity = "medium"

                        await self._save_observation(
                            asset_id=asset_id,
                            status_code=None,
                            page_title=None,
                            tech_stack={"service_worker": {
                                "scriptURL": script_url,
                                "scope": scope,
                            }},
                            headers=None,
                        )

                        if details:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity=severity,
                                title=f"Service worker risk on {domain}",
                                description=(
                                    f"Service worker at {script_url} with scope "
                                    f"{scope} detected on {domain}. "
                                    + "; ".join(details)
                                ),
                            )
                            risky_patterns += len(details)

                    # -------------------------------------------------
                    # Phase 2: Probe common SW file paths via HTTP
                    # -------------------------------------------------
                    for sw_path in SW_PATHS:
                        try:
                            probe_url = f"https://{domain}{sw_path}"
                            resp = await client.get(probe_url)

                            if resp.status_code == 200:
                                content_type = resp.headers.get("content-type", "")
                                if "javascript" in content_type or "text/" in content_type:
                                    sw_source = resp.text
                                    workers_found += 1

                                    risks = self._check_risky_patterns(sw_source)
                                    risky_patterns += len(risks)

                                    sw_severity = "medium" if risks else "info"

                                    await self._save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity=sw_severity,
                                        title=f"Service worker file found: {sw_path} on {domain}",
                                        description=(
                                            f"Accessible service worker at {probe_url}. "
                                            + (
                                                f"Risky patterns: {', '.join(risks)}."
                                                if risks
                                                else "No risky patterns detected."
                                            )
                                        ),
                                        poc=probe_url,
                                    )
                        except Exception as exc:
                            log.debug(
                                f"Failed to probe {sw_path} on {domain}: {exc}",
                                extra={"domain": domain},
                            )

                except Exception as exc:
                    log.warning(
                        f"Failed to audit service workers on {domain}: {exc}",
                        extra={"domain": domain},
                    )
                finally:
                    if page is not None:
                        await browser_mgr.release_page(page)
        finally:
            if should_close:
                await client.aclose()

        # 5. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "workers_found": workers_found,
            "risky_patterns": risky_patterns,
            "urls_checked": urls_checked,
            "skipped_cooldown": False,
        }
        log.info("service_worker_auditor complete", extra=stats)
        return stats
