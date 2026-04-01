"""Client-side authentication tester (WSTG-CLIENT-10)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientAuthTester(ClientSideTool):
    """Tests for client-side authentication weaknesses including
    token storage, session management, and auth bypass via client manipulation.
    """

    name = "client_auth_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "client_auth_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
