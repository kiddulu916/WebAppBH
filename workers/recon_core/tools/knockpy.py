"""Knockpy wrapper — active subdomain enumeration."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Knockpy(ReconTool):
    name = "knockpy"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["knockpy", target.base_domain]

    def parse_output(self, stdout):
        return [
            line.strip()
            for line in stdout.strip().splitlines()
            if line.strip() and "." in line
        ]
