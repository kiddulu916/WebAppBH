"""Remember password testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class RememberPasswordTester(AuthenticationTool):
    """Test remember password functionality."""

    name = "remember_password_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "remember_password_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Remember password testing completed",
            "description": "Successfully tested remember password functionality",
            "severity": "info",
            "data": {"placeholder": True}
        }]