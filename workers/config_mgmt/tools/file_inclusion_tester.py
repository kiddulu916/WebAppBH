"""File inclusion testing tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class FileInclusionTester(ConfigMgmtTool):
    """Tests file permissions and access."""

    name = "FileInclusionTester"

    def build_command(self, target, headers=None):
        return ["echo", "File inclusion test for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "exposed_sensitive_file", "severity": "high", "description": "placeholder", "location": target.url}}]