"""DomClobberingDetector -- Stage 3 browser-based DOM clobbering detector.

Navigates live pages and scans for HTML elements whose ``id`` or ``name``
attributes shadow built-in browser globals, which can be exploited by
attackers to hijack control flow or exfiltrate data.
"""

from __future__ import annotations

import json

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("dom-clobbering")

# Global names that, when clobbered by an element's id/name, can lead to
# security issues (e.g. redirecting ``location``, overriding ``fetch``).
CLOBBERABLE_GLOBALS = [
    "location", "self", "top", "parent", "frames",
    "document", "fetch", "alert", "confirm",
    "name", "origin", "status",
]

# JavaScript expression evaluated in the page context that returns an array
# of ``{tag, attr}`` objects for every element whose id or name collides
# with a clobberable global.
DETECT_EXPR = """(() => {
  const globals = %s;
  const found = [];
  document.querySelectorAll('[id],[name]').forEach(el => {
    const val = el.id || el.getAttribute('name');
    if (globals.includes(val)) found.push({tag: el.tagName, attr: val});
  });
  return found;
})()""" % json.dumps(CLOBBERABLE_GLOBALS)


class DomClobberingDetector(WebAppTool):
    """Detect DOM elements that shadow critical browser globals."""

    name = "dom_clobbering"
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
        """Scan live URLs for DOM clobbering risks.

        Returns a stats dict with keys: urls_checked, clobbering_risks,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="dom_clobbering")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping dom_clobbering -- within cooldown period")
            return {
                "urls_checked": 0,
                "clobbering_risks": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning(
                "No BrowserManager provided -- skipping dom_clobbering"
            )
            return {
                "urls_checked": 0,
                "clobbering_risks": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found -- nothing to check")
            return {
                "urls_checked": 0,
                "clobbering_risks": 0,
                "skipped_cooldown": False,
            }

        urls_checked = 0
        clobbering_risks = 0

        # 4. Iterate each domain
        for asset_id, domain in urls:
            page = None
            try:
                page = await browser_mgr.new_page(headers=headers)
                await page.goto(
                    f"https://{domain}", wait_until="networkidle"
                )
                urls_checked += 1

                # Evaluate the clobbering detection expression
                findings = await page.evaluate(DETECT_EXPR)

                for finding in findings:
                    tag = finding.get("tag", "UNKNOWN")
                    attr = finding.get("attr", "")
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="medium",
                        title=(
                            f"DOM clobbering risk: <{tag.lower()}> shadows "
                            f"'{attr}' on {domain}"
                        ),
                        description=(
                            f"An HTML <{tag.lower()}> element with "
                            f"id/name=\"{attr}\" shadows the global "
                            f"``window.{attr}``. If attacker-controlled "
                            f"HTML is injected, this can hijack the "
                            f"clobbered property to alter page behavior."
                        ),
                    )
                    clobbering_risks += 1

            except Exception as exc:
                log.warning(
                    f"Failed to check DOM clobbering on {domain}: {exc}",
                    extra={"domain": domain},
                )
            finally:
                if page is not None:
                    await browser_mgr.release_page(page)

        # 5. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "clobbering_risks": clobbering_risks,
            "skipped_cooldown": False,
        }
        log.info("dom_clobbering complete", extra=stats)
        return stats
