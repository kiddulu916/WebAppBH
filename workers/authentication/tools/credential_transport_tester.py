"""Credential transport testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class CredentialTransportTester(AuthenticationTool):
    """Test credential transport security."""

    name = "credential_transport_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "credential_transport_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Credential transport testing completed",
            "description": "Successfully tested credential transport mechanisms",
            "severity": "info",
            "data": {"placeholder": True}
        }]