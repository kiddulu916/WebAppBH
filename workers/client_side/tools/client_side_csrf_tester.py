"""Client-side CSRF token tester (WSTG-CLIENT-03)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientSideCsrfTester(ClientSideTool):
    """Tests for client-side CSRF token handling weaknesses,
    including missing tokens, predictable tokens, and token reuse.
    """

    name = "client_side_csrf_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "client_side_csrf_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
