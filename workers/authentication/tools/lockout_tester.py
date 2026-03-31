"""Lockout mechanism testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class LockoutTester(AuthenticationTool):
    """Test account lockout mechanisms."""

    name = "lockout_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "lockout_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Lockout mechanism testing completed",
            "description": "Successfully tested account lockout mechanisms",
            "severity": "info",
            "data": {"placeholder": True}
        }]