"""CSP bypass tester (WSTG-CLIENT-04)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class CspBypassTester(ClientSideTool):
    """Tests for Content-Security-Policy bypass techniques
    including unsafe-inline, unsafe-eval, and overly permissive sources.
    """

    name = "csp_bypass_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "csp_bypass_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
