"""Gauplus wrapper — URL discovery from multiple sources."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Gauplus(ReconTool):
    name = "gauplus"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["gauplus", "-t", "5", "-random-agent", target.base_domain]

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
