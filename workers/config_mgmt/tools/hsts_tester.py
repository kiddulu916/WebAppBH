"""HSTS testing tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class HstsTester(ConfigMgmtTool):
    """Tests HTTP Strict Transport Security."""

    name = "HstsTester"

    def build_command(self, target, headers=None):
        return ["echo", "HSTS test for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "missing_hsts", "severity": "medium", "description": "placeholder", "location": target.url}}]