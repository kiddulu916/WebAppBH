"""Knockpy wrapper — DNS subdomain scanning."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Knockpy(ReconTool):
    name = "knockpy"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["knockpy", target.base_domain, "--json"]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    for domain in data.keys():
                        if "." in domain:
                            results.append(domain)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, str) and "." in item:
                            results.append(item)
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    results.append(line)
        return results
