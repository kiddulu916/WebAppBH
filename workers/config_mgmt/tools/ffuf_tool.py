"""Ffuf directory/file fuzzing tool for config management."""

import json
import os
import tempfile

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass

SMALL_WORDLIST = os.environ.get("WORDLIST_SMALL", "/app/wordlists/common.txt")
LARGE_WORDLIST = os.environ.get("WORDLIST_LARGE", "/app/wordlists/directory-list-2.3-medium.txt")
RATE_THRESHOLD = 50


class FfufTool(ConfigMgmtTool):
    """Directory and file fuzzing with ffuf (WSTG-CONFIG-004)."""

    name = "FfufTool"

    @property
    def weight_class(self) -> WeightClass:
        return WeightClass.HEAVY

    def _choose_wordlist(self, rate_limit: int) -> str:
        return LARGE_WORDLIST if rate_limit >= RATE_THRESHOLD else SMALL_WORDLIST

    def build_command(self, target, headers=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
        url = base_url.rstrip("/") + "/FUZZ"

        rate_limit = int(os.environ.get("RATE_LIMIT", "50"))
        wordlist = self._choose_wordlist(rate_limit)
        output_file = tempfile.mktemp(suffix=".json", prefix="ffuf_")

        cmd = [
            "ffuf", "-u", url, "-w", wordlist,
            "-o", output_file, "-of", "json",
            "-mc", "200,204,301,302,307,401,403",
            "-rate", str(rate_limit),
            "-t", str(min(rate_limit, 50)),
        ]
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        self._output_file = output_file
        return cmd

    def parse_output(self, stdout):
        output_file = getattr(self, "_output_file", None)
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    data = json.load(f)
                os.unlink(output_file)
                results = []
                for entry in data.get("results", []):
                    path = entry.get("input", {}).get("FUZZ", entry.get("url", ""))
                    status = entry.get("status", 0)
                    length = entry.get("length", 0)
                    results.append({
                        "vulnerability": {
                            "name": f"Discovered path: /{path}",
                            "severity": "medium" if status in (200, 204) else "low",
                            "description": f"ffuf found /{path} (HTTP {status}, {length} bytes)",
                            "location": entry.get("url", f"/{path}"),
                        }
                    })
                return results
            except (json.JSONDecodeError, OSError):
                pass
        return []
