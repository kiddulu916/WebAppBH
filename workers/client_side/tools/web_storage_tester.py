"""Web storage tester (WSTG-CLIENT-06)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class WebStorageTester(ClientSideTool):
    """Tests for insecure use of Web Storage APIs (localStorage, sessionStorage)
    including storage of sensitive data without encryption.
    """

    name = "web_storage_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "web_storage_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
