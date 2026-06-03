# workers/info_gathering/tools/paramspider.py
"""Paramspider wrapper — parameter discovery from web archives."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class Paramspider(InfoGatheringTool):
    """Parameter discovery using Paramspider."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target:
            return

        cmd = ["paramspider", "-d", target.base_domain, "--json"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=600)
        except Exception as exc:
            logger.error("paramspider subprocess failed", extra={"domain": target.base_domain, "error": str(exc)})
            return

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                params = data.get("params", [])
                if url:
                    url_asset_id = await self.save_asset(target_id, "url", url, "paramspider")
                    if url_asset_id and params:
                        await self.save_observation(
                            asset_id=url_asset_id,
                            tech_stack={"_source": "paramspider", "url": url, "params": params},
                        )
            except json.JSONDecodeError:
                if "=" in line:
                    await self.save_asset(target_id, "url", line, "paramspider")