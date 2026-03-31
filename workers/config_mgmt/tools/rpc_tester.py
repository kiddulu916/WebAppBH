"""RPC testing tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class RpcTester(ConfigMgmtTool):
    """Tests cross-domain policy files."""

    name = "RpcTester"

    def build_command(self, target, headers=None):
        return ["echo", "RPC test for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "permissive_cross_domain", "severity": "high", "description": "placeholder", "location": target.url}}]