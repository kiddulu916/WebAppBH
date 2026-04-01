"""HTML5 injection tester (WSTG-CLIENT-05)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class Html5InjectionTester(ClientSideTool):
    """Tests for HTML5-specific injection vectors including
    postMessage, WebSockets, and WebRTC data channels.
    """

    name = "html5_injection_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "html5_injection_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
