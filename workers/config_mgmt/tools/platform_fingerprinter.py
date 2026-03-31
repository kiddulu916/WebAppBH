"""Platform fingerprinting tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class PlatformFingerprinter(ConfigMgmtTool):
    """Fingerprints web server and application platform."""

    name = "PlatformFingerprinter"

    def build_command(self, target, headers=None):
        return ["echo", "Platform fingerprint for", target.url]

    def parse_output(self, stdout):
        return [{"observation": {"type": "platform_fingerprint", "value": "placeholder", "details": {}}}]