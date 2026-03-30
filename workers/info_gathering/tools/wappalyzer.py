# workers/info_gathering/tools/wappalyzer.py
"""Wappalyzer wrapper — technology detection."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool


class Wappalyzer(InfoGatheringTool):
    """Technology detection using Wappalyzer."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["wappalyzer", f"https://{target.base_domain}"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=300)
        except Exception:
            return

        try:
            data = json.loads(stdout)
            techs = data.get("technologies", [])
            if techs:
                await self.save_observation(
                    target_id, "technology_detection",
                    {"host": target.base_domain, "technologies": [t.get("name", "") for t in techs]},
                    "wappalyzer"
                )
        except json.JSONDecodeError:
            pass