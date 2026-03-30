# workers/info_gathering/tools/webanalyze.py
"""Webanalyze wrapper — technology detection using Wappalyzer database."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool


class Webanalyze(InfoGatheringTool):
    """Technology detection using Webanalyze."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["webanalyze", "-host", target.base_domain, "-output", "json"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=300)
        except Exception:
            return

        try:
            data = json.loads(stdout)
            matches = data.get("matches", [])
            if matches:
                techs = [m.get("app_name", "") for m in matches if m.get("app_name")]
                await self.save_observation(
                    target_id, "technology_detection",
                    {"host": target.base_domain, "technologies": techs},
                    "webanalyze"
                )
        except json.JSONDecodeError:
            pass