# workers/info_gathering/tools/archive_prober.py
"""ArchiveProber wrapper — probe web archives for historical data."""

import aiohttp
import json

from workers.info_gathering.base_tool import InfoGatheringTool


class ArchiveProber(InfoGatheringTool):
    """Probe web archives for historical snapshots and URLs."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        # Query Wayback Machine CDX API
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://web.archive.org/cdx/search/cdx?url={target.base_domain}/*&output=json&limit=500"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for row in data[1:]:  # Skip header row
                            if len(row) >= 3:
                                original_url = row[2]
                                await self.save_asset(target_id, "url", original_url, "archive_prober")
        except Exception:
            pass