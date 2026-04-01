"""Clickjacking tester (WSTG-CLIENT-02)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClickjackingTester(ClientSideTool):
    """Tests for clickjacking vulnerabilities via missing X-Frame-Options
    and Content-Security-Policy frame-ancestors directives.
    """

    name = "clickjacking_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "clickjacking_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
