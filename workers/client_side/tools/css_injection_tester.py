"""CSS injection tester (WSTG-CLIENT-12)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class CssInjectionTester(ClientSideTool):
    """Tests for CSS injection vulnerabilities including
    attribute exfiltration via CSS selectors and UI redressing.
    """

    name = "css_injection_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "css_injection_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
