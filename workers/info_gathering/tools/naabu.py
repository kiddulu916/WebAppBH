# workers/info_gathering/tools/naabu.py
"""Naabu wrapper — fast port scanning."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool


class Naabu(InfoGatheringTool):
    """Fast port scanning using Naabu."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["naabu", "-host", target.base_domain, "-json", "-silent"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=600)
        except Exception:
            return

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                port = data.get("port")
                if host and port:
                    await self.save_observation(
                        target_id, "port_scan",
                        {"host": host, "port": port, "protocol": "tcp"},
                        "naabu"
                    )
            except json.JSONDecodeError:
                continue