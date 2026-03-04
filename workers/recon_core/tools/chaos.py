"""Chaos (ProjectDiscovery) wrapper — passive subdomain enumeration."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Chaos(ReconTool):
    name = "chaos"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["chaos", "-d", target.base_domain, "-silent", "-json"]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", data.get("subdomain", ""))
                if host:
                    results.append(host)
            except json.JSONDecodeError:
                results.append(line)
        return results
