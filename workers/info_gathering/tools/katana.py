# workers/info_gathering/tools/katana.py
"""Katana wrapper — web crawling and path discovery."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool


class Katana(InfoGatheringTool):
    """Web crawling using Katana."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = [
            "katana", "-u", f"https://{target.base_domain}",
            "-json", "-silent", "-d", "3",
        ]
        try:
            stdout = await self.run_subprocess(cmd, timeout=900)
        except Exception:
            return

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url:
                    await self.save_asset(target_id, "url", url, "katana")
            except json.JSONDecodeError:
                if line.startswith("http"):
                    await self.save_asset(target_id, "url", line, "katana")