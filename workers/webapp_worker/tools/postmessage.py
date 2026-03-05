"""PostMessage — Stage 3 browser-based postMessage listener audit.

Hooks EventTarget.addEventListener to intercept "message" event handlers,
inspects them for origin validation, and flags insecure listeners as
high-severity vulnerabilities.
"""

from __future__ import annotations

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("postmessage")

# JavaScript injected via addInitScript *before* page scripts execute.
# It monkey-patches EventTarget.prototype.addEventListener to capture
# any "message" handler registrations and inspect their source for
# origin-validation patterns.
HOOK_SCRIPT = """
(() => {
    window.__postMessageListeners = [];
    const _origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, fn, opts) {
        if (type === "message" && typeof fn === "function") {
            const src = fn.toString();
            const hasOriginCheck = /event\\.origin|e\\.origin|\\.origin\\s*===|\\.origin\\s*==|\\.origin\\s*!==|\\.origin\\s*!=/.test(src);
            window.__postMessageListeners.push({
                has_origin_check: hasOriginCheck,
                handler_preview: src.slice(0, 200)
            });
        }
        return _origAdd.call(this, type, fn, opts);
    };
})();
"""

# Expression evaluated after page load to retrieve captured listeners.
COLLECT_EXPR = "() => window.__postMessageListeners || []"


class PostMessage(WebAppTool):
    """Detect insecure postMessage listeners on live web pages."""

    name = "postmessage"
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
        """Crawl live URLs, hook message listeners, and flag insecure ones.

        Returns a stats dict with keys: domains_checked, insecure_listeners,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="postmessage")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping postmessage — within cooldown period")
            return {
                "domains_checked": 0,
                "insecure_listeners": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning("No BrowserManager provided — skipping postmessage")
            return {
                "domains_checked": 0,
                "insecure_listeners": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found — nothing to check")
            return {
                "domains_checked": 0,
                "insecure_listeners": 0,
                "skipped_cooldown": False,
            }

        domains_checked = 0
        insecure_count = 0

        # 4. Iterate each domain
        for asset_id, domain in urls:
            page = None
            try:
                page = await browser_mgr.new_page(headers=headers)

                # Inject the hook before any page script runs
                await page.add_init_script(HOOK_SCRIPT)

                # Navigate
                url = f"https://{domain}"
                await page.goto(url, wait_until="networkidle")

                # Collect captured listeners
                listeners = await page.evaluate(COLLECT_EXPR)
                domains_checked += 1

                # 5. Flag insecure listeners
                for listener in listeners:
                    if not listener.get("has_origin_check", True):
                        preview = listener.get("handler_preview", "")
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=f"Insecure postMessage listener on {domain}",
                            description=(
                                "A postMessage event handler was registered without "
                                "origin validation. An attacker can send arbitrary "
                                "messages from any origin.\n\n"
                                f"Handler preview:\n```\n{preview}\n```"
                            ),
                        )
                        insecure_count += 1

            except Exception as exc:
                log.warning(
                    f"Failed to check postMessage on {domain}: {exc}",
                    extra={"domain": domain},
                )
            finally:
                if page is not None:
                    await browser_mgr.release_page(page)

        # 6. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "domains_checked": domains_checked,
            "insecure_listeners": insecure_count,
            "skipped_cooldown": False,
        }
        log.info("postmessage complete", extra=stats)
        return stats
