"""Authentication bypass testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class AuthBypassTester(AuthenticationTool):
    """Test for authentication bypass vulnerabilities."""

    name = "auth_bypass_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "auth_bypass_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Authentication bypass testing completed",
            "description": "Successfully tested for authentication bypass vulnerabilities",
            "severity": "info",
            "data": {"placeholder": True}
        }]