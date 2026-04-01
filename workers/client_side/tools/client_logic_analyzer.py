"""Client-side logic analyzer (WSTG-CLIENT-07)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientLogicAnalyzer(ClientSideTool):
    """Analyzes client-side business logic enforcement,
    identifying logic that should be server-side validated.
    """

    name = "client_logic_analyzer"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "client_logic_analyzer_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
