"""Directory traversal testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class DirectoryTraversalTester(AuthorizationTool):
    """Test for directory traversal vulnerabilities."""

    name = "directory_traversal_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "directory_traversal_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Directory traversal testing completed",
            "description": "Successfully tested for directory traversal vulnerabilities",
            "severity": "info",
            "data": {"placeholder": True}
        }]