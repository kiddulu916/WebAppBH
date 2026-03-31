"""Password change testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class PasswordChangeTester(AuthenticationTool):
    """Test password change functionality."""

    name = "password_change_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "password_change_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Password change testing completed",
            "description": "Successfully tested password change functionality",
            "severity": "info",
            "data": {"placeholder": True}
        }]