# workers/info_gathering/tools/paramspider.py
"""Paramspider wrapper — parameter discovery from web archives."""

from workers.info_gathering.base_tool import InfoGatheringTool


class Paramspider(InfoGatheringTool):
    """Parameter discovery using Paramspider."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["paramspider", "-d", target.base_domain, "--json"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=600)
        except Exception:
            return

        import json
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                params = data.get("params", [])
                if url:
                    await self.save_asset(target_id, "url", url, "paramspider")
                    for param in params:
                        await self.save_observation(
                            target_id, "parameter",
                            {"url": url, "param": param},
                            "paramspider"
                        )
            except json.JSONDecodeError:
                if "=" in line:
                    await self.save_asset(target_id, "url", line, "paramspider")