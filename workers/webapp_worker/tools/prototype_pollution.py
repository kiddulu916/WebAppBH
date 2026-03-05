"""PrototypePollution -- Stage 3 browser-based prototype pollution detector.

Navigates live pages, injects a detection script that monitors writes to
Object.prototype, and probes URL-based pollution payloads to detect
client-side prototype pollution vulnerabilities.
"""

from __future__ import annotations

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("prototype-pollution")

# JavaScript injected via add_init_script *before* page scripts execute.
# Wraps Object.prototype.__proto__ in a Proxy to detect property writes.
DETECT_SCRIPT = """
(() => {
  window.__pp_detected = [];
  const handler = {
    set(target, prop, value) {
      window.__pp_detected.push({prop, value: String(value)});
      return Reflect.set(target, prop, value);
    }
  };
  try {
    Object.prototype.__proto__ = new Proxy(Object.prototype.__proto__, handler);
  } catch(e) {}
})()
"""

# URL payloads that attempt to pollute Object.prototype via query parameters.
PP_PAYLOADS = [
    "?__proto__[pptest]=true",
    "?constructor[prototype][pptest]=true",
    "?__proto__.pptest=true",
]

# Expression to check whether the pollution payload was effective.
PP_CHECK_EXPR = "(() => { const o = {}; return o.pptest === 'true'; })()"

# Expression to collect any detections captured by the init script.
COLLECT_EXPR = "() => window.__pp_detected || []"


class PrototypePollution(WebAppTool):
    """Detect client-side prototype pollution on live web pages."""

    name = "prototype_pollution"
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
        """Probe live URLs for prototype pollution vulnerabilities.

        Returns a stats dict with keys: urls_checked, vulns_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="prototype_pollution")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping prototype_pollution -- within cooldown period")
            return {
                "urls_checked": 0,
                "vulns_found": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning("No BrowserManager provided -- skipping prototype_pollution")
            return {
                "urls_checked": 0,
                "vulns_found": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found -- nothing to check")
            return {
                "urls_checked": 0,
                "vulns_found": 0,
                "skipped_cooldown": False,
            }

        urls_checked = 0
        vulns_found = 0

        # 4. Iterate each domain
        for asset_id, domain in urls:
            page = None
            try:
                page = await browser_mgr.new_page(headers=headers)

                # Inject the detection proxy before page scripts run
                await page.add_init_script(DETECT_SCRIPT)

                # Navigate to the base page
                base_url = f"https://{domain}"
                await page.goto(base_url, wait_until="networkidle")
                urls_checked += 1

                # Check for detections captured by the init-script proxy
                detections = await page.evaluate(COLLECT_EXPR)
                if detections:
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="high",
                        title=f"Prototype pollution detected on {domain}",
                        description=(
                            "The page's own scripts write to Object.prototype, "
                            "indicating a prototype pollution sink.\n\n"
                            f"Detected properties: {detections}"
                        ),
                    )
                    vulns_found += 1

                # 5. URL-based payload probing
                for payload in PP_PAYLOADS:
                    probe_page = None
                    try:
                        probe_page = await browser_mgr.new_page(headers=headers)
                        probe_url = f"{base_url}/{payload}"
                        await probe_page.goto(probe_url, wait_until="networkidle")

                        polluted = await probe_page.evaluate(PP_CHECK_EXPR)
                        if polluted:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title=(
                                    f"URL-based prototype pollution on {domain}"
                                ),
                                description=(
                                    "A URL payload successfully polluted "
                                    "Object.prototype. An attacker can inject "
                                    "arbitrary properties into every JS object.\n\n"
                                    f"Payload: {payload}"
                                ),
                                poc=f"{base_url}/{payload}",
                            )
                            vulns_found += 1
                            break  # one proof-of-concept is sufficient
                    except Exception as exc:
                        log.debug(
                            f"Payload probe failed on {domain}: {exc}",
                            extra={"domain": domain, "payload": payload},
                        )
                    finally:
                        if probe_page is not None:
                            await browser_mgr.release_page(probe_page)

            except Exception as exc:
                log.warning(
                    f"Failed to check prototype pollution on {domain}: {exc}",
                    extra={"domain": domain},
                )
            finally:
                if page is not None:
                    await browser_mgr.release_page(page)

        # 6. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "vulns_found": vulns_found,
            "skipped_cooldown": False,
        }
        log.info("prototype_pollution complete", extra=stats)
        return stats
