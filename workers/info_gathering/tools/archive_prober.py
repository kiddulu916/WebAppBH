# workers/info_gathering/tools/archive_prober.py
"""ArchiveProber — probe Wayback Machine for historical data and cached sensitive content."""

import asyncio
from urllib.parse import urlparse

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger
from workers.info_gathering.tools.url_classifier import classify_url

# Extensions that may contain sensitive data worth fetching from the archive
SENSITIVE_EXTENSIONS = {".env", ".sql", ".bak", ".conf", ".key", ".pem", ".log",
                        ".cfg", ".ini", ".yml", ".yaml", ".properties", ".xml",
                        ".json", ".config", ".old", ".backup", ".dump"}

MAX_CACHED_FETCHES = 20


class ArchiveProber(InfoGatheringTool):
    """Probe Wayback Machine CDX API for historical snapshots and cached content.

    Identifies pages that existed in the past but may no longer be linked.
    Fetches cached content from the archive for sensitive file types
    (.env, .sql, .bak, etc.) and stores them as Observations.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")
        rate_limiter = kwargs.get("rate_limiter")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        discovered_urls: set[str] = set()
        sensitive_urls: list[tuple[str, str]] = []  # (url, timestamp)

        # Query Wayback Machine CDX API
        try:
            await self.acquire_rate_limit(rate_limiter)
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                cdx_url = (
                    f"http://web.archive.org/cdx/search/cdx"
                    f"?url={domain}/*&output=json&limit=1000&fl=timestamp,original,statuscode"
                    f"&collapse=urlkey"
                )
                async with session.get(cdx_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for row in data[1:]:  # Skip header row
                            if len(row) >= 3:
                                timestamp, original_url, status = row[0], row[1], row[2]
                                if status and status.startswith(("2", "3")):
                                    discovered_urls.add(original_url)
                                    # Check for sensitive extensions
                                    parsed = urlparse(original_url)
                                    path = parsed.path.lower()
                                    if any(path.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
                                        sensitive_urls.append((original_url, timestamp))
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"CDX API request failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error querying CDX: {e}")

        # Save all discovered URLs as assets with classified types
        saved = 0
        for url in discovered_urls:
            asset_type = classify_url(url)
            asset_id = await self.save_asset(
                target_id, asset_type, url, "archive_prober",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        # Fetch cached content for sensitive files (capped)
        observations_saved = 0
        fetched = 0
        for url, timestamp in sensitive_urls[:MAX_CACHED_FETCHES]:
            await self.acquire_rate_limit(rate_limiter)
            content = await self._fetch_cached_content(url, timestamp)
            if content:
                # Save as observation — first 2KB as snippet
                snippet = content[:2048]
                # Need an asset to attach observation to — find or create one
                asset_id = await self.save_asset(
                    target_id, "sensitive_file", url, "archive_prober",
                    scope_manager=scope_manager,
                )
                if asset_id:
                    await self.save_observation(
                        asset_id,
                        tech_stack={"source": "wayback_cached", "timestamp": timestamp},
                        page_title=f"Cached: {url}",
                        headers={"content_snippet": snippet},
                    )
                    observations_saved += 1
            fetched += 1

        return {"found": saved, "cached_fetched": fetched, "observations": observations_saved}

    async def _fetch_cached_content(self, url: str, timestamp: str) -> str | None:
        """Fetch a cached page from the Wayback Machine. Returns text or None."""
        wayback_url = f"https://web.archive.org/web/{timestamp}id_/{url}"
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(wayback_url) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None
