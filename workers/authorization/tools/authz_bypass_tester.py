"""Authorization bypass testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class AuthzBypassTester(AuthorizationTool):
    """Test for authorization bypass vulnerabilities."""

    name = "authz_bypass_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "authz_bypass_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Authorization bypass testing completed",
            "description": "Successfully tested for authorization bypass vulnerabilities",
            "severity": "info",
            "data": {"placeholder": True}
        }]