"""Katana wrapper — web crawling."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Katana(ReconTool):
    name = "katana"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        cmd = ["katana", "-u", target.base_domain, "-silent", "-depth", "3"]
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
