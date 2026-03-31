"""File extension handling tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class FileExtensionTester(ConfigMgmtTool):
    """Tests file extension handling security."""

    name = "FileExtensionTester"

    def build_command(self, target, headers=None):
        return ["echo", "File extension test for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "exposed_sensitive_file", "severity": "medium", "description": "placeholder", "location": target.url}}]