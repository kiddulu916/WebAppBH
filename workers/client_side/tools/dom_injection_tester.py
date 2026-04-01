"""DOM-based injection tester (WSTG-CLIENT-08)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class DomInjectionTester(ClientSideTool):
    """Tests for DOM-based injection beyond XSS, including
    DOM Clobbering and prototype pollution vectors.
    """

    name = "dom_injection_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "dom_injection_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
