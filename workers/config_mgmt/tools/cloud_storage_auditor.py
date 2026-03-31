"""Cloud storage auditor."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class CloudStorageAuditor(ConfigMgmtTool):
    """Audits cloud storage configurations."""

    name = "CloudStorageAuditor"

    def build_command(self, target, headers=None):
        return ["echo", "Cloud storage audit for", target.url]

    def parse_output(self, stdout):
        return [{"vulnerability": {"name": "exposed_cloud_storage", "severity": "high", "description": "placeholder", "location": target.url}}]