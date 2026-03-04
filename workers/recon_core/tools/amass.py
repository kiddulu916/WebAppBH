"""Amass wrapper — both passive and active modes."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class AmassPassive(ReconTool):
    name = "amass_passive"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        return [
            "amass", "enum", "-passive", "-d", target.base_domain,
            "-json", "/dev/stdout",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    results.append(name)
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    results.append(line)
        return results


class AmassActive(ReconTool):
    name = "amass_active"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        return [
            "amass", "enum", "-active", "-d", target.base_domain,
            "-json", "/dev/stdout",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    results.append(name)
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    results.append(line)
        return results
