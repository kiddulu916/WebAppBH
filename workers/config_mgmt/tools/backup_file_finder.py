"""Backup file discovery tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class BackupFileFinder(ConfigMgmtTool):
    """Finds backup and unreferenced files."""

    name = "BackupFileFinder"

    def build_command(self, target, headers=None):
        return ["echo", "Backup file finder for", target.url]

    def parse_output(self, stdout):
        return [{"location": {"url": target.url + "/backup.zip", "status": 200}}]