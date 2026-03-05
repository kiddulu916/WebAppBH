"""DomSinkAnalyzer — Stage 3 static + dynamic DOM XSS detection.

Phase 1 (static): Scans saved JavaScript files for dangerous DOM sinks
combined with user-controllable sources to flag potential DOM-based XSS.

Phase 2 (dynamic): Uses Playwright to inject a probe parameter and check
whether the value is reflected in the DOM.
"""

from __future__ import annotations

import os
import re

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("dom-sink-analyzer")

# Base directory for raw JS file storage.  Tests patch this to tmp_path.
JS_DIR = "/app/shared/raw"

# -----------------------------------------------------------------------
# Dangerous DOM sink patterns
# -----------------------------------------------------------------------
SINK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.innerHTML\s*="), "innerHTML assignment"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML assignment"),
    (re.compile(r"\.insertAdjacentHTML\s*\("), "insertAdjacentHTML call"),
    (re.compile(r"\bsetTimeout\s*\(\s*[^,)]*[a-zA-Z]"), "setTimeout with dynamic arg"),
    (re.compile(r"\bsetInterval\s*\(\s*[^,)]*[a-zA-Z]"), "setInterval with dynamic arg"),
    (re.compile(r"new\s+Function\s*\("), "Function constructor"),
    (re.compile(r"\.setAttribute\s*\(\s*['\"]on"), "setAttribute with event handler"),
    (re.compile(r"location\s*="), "location assignment"),
    (re.compile(r"location\.href\s*="), "location.href assignment"),
]

# -----------------------------------------------------------------------
# User-controllable source patterns
# -----------------------------------------------------------------------
SOURCE_PATTERNS: list[re.Pattern] = [
    re.compile(r"location\.hash"),
    re.compile(r"location\.search"),
    re.compile(r"location\.href"),
    re.compile(r"document\.referrer"),
    re.compile(r"window\.name"),
    re.compile(r"URLSearchParams"),
]


def _find_sinks(js_content: str) -> list[str]:
    """Scan *js_content* for dangerous DOM sink patterns.

    Returns a list of human-readable descriptions for each match.
    """
    found: list[str] = []
    for pattern, description in SINK_PATTERNS:
        if pattern.search(js_content):
            found.append(description)
    return found


def _find_sources(js_content: str) -> list[str]:
    """Scan *js_content* for user-controllable source patterns.

    Returns the matched source pattern strings.
    """
    found: list[str] = []
    for pattern in SOURCE_PATTERNS:
        match = pattern.search(js_content)
        if match:
            found.append(match.group())
    return found


class DomSinkAnalyzer(WebAppTool):
    """Detect potential DOM-based XSS via static analysis and dynamic probing."""

    name = "dom_sink_analyzer"
    tool_type = ToolType.BROWSER
    weight_class = WeightClass.HEAVY

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run static + dynamic DOM XSS analysis.

        Returns a stats dict with keys: files_scanned, sinks_found,
        source_sink_vulns, reflected_vulns, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="dom_xss")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping dom_sink_analyzer — within cooldown period")
            return {
                "files_scanned": 0,
                "sinks_found": 0,
                "source_sink_vulns": 0,
                "reflected_vulns": 0,
                "skipped_cooldown": True,
            }

        files_scanned = 0
        sinks_found = 0
        source_sink_vulns = 0
        reflected_vulns = 0

        # ---------------------------------------------------------------
        # Phase 1 — Static analysis of saved JS files
        # ---------------------------------------------------------------
        js_dir = os.path.join(JS_DIR, str(target_id), "js")
        if os.path.isdir(js_dir):
            for filename in os.listdir(js_dir):
                if not filename.endswith(".js"):
                    continue
                filepath = os.path.join(js_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except OSError:
                    continue

                files_scanned += 1
                sinks = _find_sinks(content)
                sources = _find_sources(content)
                sinks_found += len(sinks)

                if sinks and sources:
                    # Get live URLs to find an asset_id for this target
                    urls = await self._get_live_urls(target_id)
                    asset_id = urls[0][0] if urls else 0

                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="high",
                        title=f"Potential DOM XSS in {filename}",
                        description=(
                            f"Static analysis found dangerous sinks "
                            f"({', '.join(sinks)}) combined with "
                            f"user-controllable sources ({', '.join(sources)}) "
                            f"in {filename}."
                        ),
                    )
                    source_sink_vulns += 1

        # ---------------------------------------------------------------
        # Phase 2 — Dynamic Playwright reflection check
        # ---------------------------------------------------------------
        browser_mgr = kwargs.get("browser")
        if browser_mgr is not None:
            urls = await self._get_live_urls(target_id)
            for asset_id, domain in urls:
                page = None
                try:
                    page = await browser_mgr.new_page(headers=headers)
                    probe_url = f"https://{domain}?xss_test=probe123"
                    await page.goto(probe_url, wait_until="networkidle")

                    # Check if the probe value is reflected in the DOM
                    reflected = await page.evaluate(
                        "() => document.documentElement.innerHTML.includes('probe123')"
                    )
                    if reflected:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title="URL parameter reflected in DOM",
                            description=(
                                f"The value of the query parameter 'xss_test' "
                                f"was reflected in the DOM of {domain}. "
                                f"This may indicate a reflected or DOM-based XSS."
                            ),
                            poc=probe_url,
                        )
                        reflected_vulns += 1

                except Exception as exc:
                    log.warning(
                        f"Dynamic DOM check failed for {domain}: {exc}",
                        extra={"domain": domain},
                    )
                finally:
                    if page is not None:
                        await browser_mgr.release_page(page)

        # ---------------------------------------------------------------
        # Update state and return
        # ---------------------------------------------------------------
        await self.update_tool_state(target_id, container_name)

        stats = {
            "files_scanned": files_scanned,
            "sinks_found": sinks_found,
            "source_sink_vulns": source_sink_vulns,
            "reflected_vulns": reflected_vulns,
            "skipped_cooldown": False,
        }
        log.info("dom_sink_analyzer complete", extra=stats)
        return stats
