# workers/info_gathering/tools/katana.py
"""Katana wrapper — web crawling and path discovery."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.url_classifier import classify_url


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
                    asset_type = classify_url(url)
                    await self.save_asset(target_id, asset_type, url, "katana")
            except json.JSONDecodeError:
                if line.startswith("http"):
                    asset_type = classify_url(line)
                    await self.save_asset(target_id, asset_type, line, "katana")