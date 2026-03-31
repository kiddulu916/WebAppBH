"""API discovery tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class ApiDiscoveryTool(ConfigMgmtTool):
    """Discovers administrative interfaces."""

    name = "ApiDiscoveryTool"

    def build_command(self, target, headers=None):
        return ["echo", "API discovery for", target.url]

    def parse_output(self, stdout):
        return [{"location": {"url": target.url + "/admin", "status": 200}}]