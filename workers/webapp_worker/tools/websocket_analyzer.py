"""WebSocketAnalyzer — Stage 3 browser-based WebSocket connection audit.

Uses Playwright to intercept WebSocket connections established by web pages,
checks for authentication tokens in WS URLs, and flags unauthenticated
WebSocket connections.
"""

from __future__ import annotations

import asyncio
import re

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("websocket-analyzer")

# Patterns that indicate authentication in WebSocket URLs.
AUTH_PATTERNS = re.compile(
    r"(token=|key=|auth=|bearer=|api_key=|apikey=|access_token=)",
    re.IGNORECASE,
)

# Seconds to wait after page load for WS connections to establish.
WS_WAIT_SECONDS = 3


class WebSocketAnalyzer(WebAppTool):
    """Detect unauthenticated WebSocket connections on live pages."""

    name = "websocket_analyzer"
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
        """Intercept WebSocket connections and check for auth tokens.

        Returns a stats dict with keys: urls_checked, ws_connections,
        unauthenticated_ws, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="websocket")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping websocket_analyzer — within cooldown period")
            return {
                "urls_checked": 0,
                "ws_connections": 0,
                "unauthenticated_ws": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning("No BrowserManager provided — skipping websocket_analyzer")
            return {
                "urls_checked": 0,
                "ws_connections": 0,
                "unauthenticated_ws": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found — nothing to check")
            return {
                "urls_checked": 0,
                "ws_connections": 0,
                "unauthenticated_ws": 0,
                "skipped_cooldown": False,
            }

        urls_checked = 0
        total_ws = 0
        unauth_ws = 0

        # 4. Iterate each domain
        for asset_id, domain in urls:
            page = None
            try:
                page = await browser_mgr.new_page(headers=headers)

                # Capture WebSocket connections
                ws_list: list[dict] = []

                def on_websocket(ws):
                    ws_list.append({"url": ws.url})

                page.on("websocket", on_websocket)

                # Navigate and wait for WS connections
                await page.goto(f"https://{domain}", wait_until="networkidle")
                await asyncio.sleep(WS_WAIT_SECONDS)

                urls_checked += 1
                total_ws += len(ws_list)

                # 5. Check each WS connection for auth
                for ws_info in ws_list:
                    ws_url = ws_info.get("url", "")
                    if not AUTH_PATTERNS.search(ws_url):
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Unauthenticated WebSocket on {domain}",
                            description=(
                                f"A WebSocket connection to {ws_url} was established "
                                f"without authentication tokens in the URL. This may "
                                f"allow unauthorized access to real-time data."
                            ),
                            poc=ws_url,
                        )
                        unauth_ws += 1

                    # Save observation with WS details
                    await self._save_observation(
                        asset_id=asset_id,
                        status_code=None,
                        page_title=None,
                        tech_stack={"websocket_url": ws_url},
                        headers=None,
                    )

            except Exception as exc:
                log.warning(
                    f"Failed to analyze WebSockets on {domain}: {exc}",
                    extra={"domain": domain},
                )
            finally:
                if page is not None:
                    await browser_mgr.release_page(page)

        # 6. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "ws_connections": total_ws,
            "unauthenticated_ws": unauth_ws,
            "skipped_cooldown": False,
        }
        log.info("websocket_analyzer complete", extra=stats)
        return stats
