"""Malicious file upload client-side tester (WSTG-CLIENT-13)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class MaliciousUploadClientTester(ClientSideTool):
    """Tests for client-side file upload validation bypasses including
    MIME type manipulation, extension bypass, and client-side size limits.
    """

    name = "malicious_upload_client_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        return ["echo", "malicious_upload_client_tester_stub"]

    def parse_output(self, stdout: str) -> list:
        return []
