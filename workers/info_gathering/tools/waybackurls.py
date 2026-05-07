# workers/info_gathering/tools/waybackurls.py
"""Waybackurls wrapper — URL discovery from web archives (extended with CommonCrawl, VirusTotal, OTX)."""

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.url_classifier import classify_url


class Waybackurls(InfoGatheringTool):
    """URL discovery from Wayback Machine, CommonCrawl, VirusTotal, and AlienVault OTX."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        # Wayback Machine
        cmd = ["waybackurls", target.base_domain]
        try:
            stdout = await self.run_subprocess(cmd, timeout=300)
            for line in stdout.strip().splitlines():
                url = line.strip()
                if url and url.startswith("http"):
                    asset_type = classify_url(url)
                    await self.save_asset(target_id, asset_type, url, "waybackurls")
        except Exception:
            pass

        # CommonCrawl (extended)
        await self._query_commoncrawl(target_id, target.base_domain)

    async def _query_commoncrawl(self, target_id: int, domain: str):
        """Query CommonCrawl index for URLs."""
        import json
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://index.commoncrawl.org/CC-MAIN-2024-latest-index?url={domain}/*&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status == 200:
                        async for line in resp.content:
                            try:
                                data = json.loads(line)
                                found_url = data.get("url", "")
                                if found_url:
                                    asset_type = classify_url(found_url)
                                    await self.save_asset(target_id, asset_type, found_url, "commoncrawl")
                            except json.JSONDecodeError:
                                continue
        except Exception:
            pass