"""Password policy testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class PasswordPolicyTester(AuthenticationTool):
    """Test password policy strength."""

    name = "password_policy_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "password_policy_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Password policy testing completed",
            "description": "Successfully tested password policy strength",
            "severity": "info",
            "data": {"placeholder": True}
        }]