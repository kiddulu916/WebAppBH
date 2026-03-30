# workers/info_gathering/tools/subfinder.py
"""Subfinder wrapper — passive subdomain enumeration."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool


class Subfinder(InfoGatheringTool):
    """Passive subdomain enumeration using Subfinder."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["subfinder", "-d", target.base_domain, "-silent", "-json"]
        try:
            stdout = await self.run_subprocess(cmd)
        except Exception:
            return

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

        for host in results:
            await self.save_asset(target_id, "subdomain", host, "subfinder")