"""Waybackurls wrapper — historical URL discovery."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Waybackurls(ReconTool):
    name = "waybackurls"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["waybackurls", target.base_domain]

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
