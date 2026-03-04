"""Paramspider wrapper — URL parameter extraction."""

from urllib.parse import urlparse, parse_qs

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Paramspider(ReconTool):
    name = "paramspider"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return [
            "paramspider", "-d", target.base_domain,
            "--level", "high", "-o", "/dev/stdout",
        ]

    def parse_output(self, stdout):
        results = []
        seen = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or "?" not in line:
                continue
            try:
                parsed = urlparse(line)
                params = parse_qs(parsed.query)
                for param_name in params:
                    key = (parsed.hostname or "", param_name)
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "param_name": param_name,
                            "param_value": params[param_name][0]
                            if params[param_name]
                            else None,
                            "source_url": line,
                        })
            except Exception:
                continue
        return results
