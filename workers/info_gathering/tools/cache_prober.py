# workers/info_gathering/tools/cache_prober.py
"""CacheProber — discover cached snapshots from archive.ph."""

import asyncio
import re
from urllib.parse import urlparse

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger
from workers.info_gathering.tools.url_classifier import classify_url


class CacheProber(InfoGatheringTool):
    """Probe archive.ph for cached snapshots of the target domain.

    Fetches the archive.ph page for the domain, extracts snapshot URLs,
    and retrieves cached content for files with sensitive extensions.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        discovered_urls: list[str] = []

        # Query archive.ph for cached snapshots
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://archive.ph/newest/{domain}"
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        html = await resp.text(errors="replace")
                        discovered_urls = self._extract_urls(html, domain)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"archive.ph request failed: {e}")

        # Save discovered URLs as assets with classified types
        saved = 0
        for url in set(discovered_urls):
            asset_type = classify_url(url)
            asset_id = await self.save_asset(
                target_id, asset_type, url, "cache_prober",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        return {"found": saved}

    @staticmethod
    def _extract_urls(html: str, domain: str) -> list[str]:
        """Extract URLs from archive.ph HTML page that belong to the target domain."""
        urls = []
        for match in re.finditer(r'href=["\']?(https?://[^"\'<>\s]+)', html):
            url = match.group(1)
            parsed = urlparse(url)
            if parsed.hostname and domain in parsed.hostname:
                # Skip archive.ph's own URLs
                if "archive.ph" not in parsed.hostname:
                    urls.append(url)
        return urls
