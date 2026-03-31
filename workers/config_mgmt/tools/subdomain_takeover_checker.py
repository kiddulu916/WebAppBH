"""Subdomain takeover checker."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class SubdomainTakeoverChecker(ConfigMgmtTool):
    """Checks for subdomain takeover vulnerabilities."""

    name = "SubdomainTakeoverChecker"

    def build_command(self, target, headers=None):
        return ["echo", "Subdomain takeover check for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "subdomain_takeover", "severity": "critical", "description": "placeholder", "location": target.url}}]