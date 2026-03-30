# workers/info_gathering/tools/hakrawler.py
"""Hakrawler wrapper — fast web crawling."""

from workers.info_gathering.base_tool import InfoGatheringTool


class Hakrawler(InfoGatheringTool):
    """Fast web crawling using Hakrawler."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["hakrawler", "-url", f"https://{target.base_domain}", "-depth", "3"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=600)
        except Exception:
            return

        for line in stdout.strip().splitlines():
            url = line.strip()
            if url and url.startswith("http"):
                await self.save_asset(target_id, "url", url, "hakrawler")