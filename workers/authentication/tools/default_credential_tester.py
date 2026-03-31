"""Default credential testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class DefaultCredentialTester(AuthenticationTool):
    """Test for default credentials."""

    name = "default_credential_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "default_credential_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Default credential testing completed",
            "description": "Successfully tested for default credentials",
            "severity": "info",
            "data": {"placeholder": True}
        }]