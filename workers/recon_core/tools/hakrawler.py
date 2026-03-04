"""Hakrawler wrapper — web crawling."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Hakrawler(ReconTool):
    name = "hakrawler"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        cmd = [
            "hakrawler", "-url", target.base_domain,
            "-depth", "2", "-plain",
        ]
        if headers:
            for key, value in headers.items():
                cmd.extend(["-h", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
