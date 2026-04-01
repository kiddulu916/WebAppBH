"""WebSocket injection testing tool."""

from __future__ import annotations

import aiohttp
from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass

WS_INJECTION_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "' OR '1'='1",
    "; ls -la",
    "{{7*7}}",
    "../../../../etc/passwd",
    '{"type": "admin", "action": "delete"}',
]


class WebSocketInjectionTester(InputValidationTool):
    """Test for WebSocket injection vulnerabilities."""

    name = "websocket_injection"
    weight_class = WeightClass.LIGHT

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Execute WebSocket injection tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
            for payload in WS_INJECTION_PAYLOADS:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.ws_connect(ws_url, headers=headers, timeout=10) as ws:
                            await ws.send_str(payload)
                            msg = await ws.receive(timeout=5)
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                if self.detect_vulnerability(msg.data, "xss") or self.detect_vulnerability(msg.data, "sqli"):
                                    await self._save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity="high",
                                        title="WebSocket Injection Vulnerability",
                                        description=f"WebSocket injection found at {ws_url}",
                                        poc=ws_url,
                                    )
                                    vulnerable += 1
                                    break
                except Exception:
                    continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}
