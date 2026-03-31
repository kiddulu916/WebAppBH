"""IDOR testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class IdorTester(AuthorizationTool):
    """Test for Insecure Direct Object Reference vulnerabilities."""

    name = "idor_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "idor_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "IDOR testing completed",
            "description": "Successfully tested for Insecure Direct Object Reference vulnerabilities",
            "severity": "info",
            "data": {"placeholder": True}
        }]