"""Subfinder wrapper — passive subdomain enumeration."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Subfinder(ReconTool):
    name = "subfinder"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["subfinder", "-d", target.base_domain, "-silent", "-json"]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if host:
                    results.append(host)
            except json.JSONDecodeError:
                results.append(line)
        return results
