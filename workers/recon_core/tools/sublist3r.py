"""Sublist3r wrapper — active subdomain enumeration."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Sublist3r(ReconTool):
    name = "sublist3r"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["sublist3r", "-d", target.base_domain, "-o", "/dev/stdout"]

    def parse_output(self, stdout):
        return [
            line.strip()
            for line in stdout.strip().splitlines()
            if line.strip() and "." in line
        ]
