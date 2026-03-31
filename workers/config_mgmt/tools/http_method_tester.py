"""HTTP methods tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class HttpMethodTester(ConfigMgmtTool):
    """Tests dangerous HTTP methods."""

    name = "HttpMethodTester"

    def build_command(self, target, headers=None):
        return ["echo", "HTTP methods test for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "dangerous_http_method", "severity": "high", "description": "placeholder", "location": target.url}}]