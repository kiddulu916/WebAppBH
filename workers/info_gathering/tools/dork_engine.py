# workers/info_gathering/tools/dork_engine.py
"""DorkEngine — multi-engine search dorking for WSTG-INFO-01."""

import asyncio
import random
from urllib.parse import quote_plus, urlparse

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger
from workers.info_gathering.tools.dork_patterns import get_dorks_for_domain

# Rotate real User-Agent strings to avoid detection
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_ENGINES = ["google", "bing", "duckduckgo"]


class DorkEngine(InfoGatheringTool):
    """Multi-engine search dorking for discovering exposed information.

    Generates dork patterns from the target domain, distributes them across
    search engines round-robin, scrapes results with rate limiting, and
    saves discovered URLs as assets.
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

        dorks = get_dorks_for_domain(domain)
        all_results: list[dict] = []

        # Round-robin assign dorks to engines
        engine_assignments = {e: [] for e in _ENGINES}
        for i, dork in enumerate(dorks):
            engine = _ENGINES[i % len(_ENGINES)]
            engine_assignments[engine].append(dork)

        # Scrape each engine's batch sequentially (with delays between queries)
        for engine_name, engine_dorks in engine_assignments.items():
            for dork in engine_dorks:
                try:
                    results = await self._scrape_engine(engine_name, dork)
                    all_results.extend(results)
                except Exception as e:
                    logger.warning(
                        f"Dork query failed on {engine_name}",
                        extra={"dork": dork, "error": str(e)},
                    )
                # Rate limit: 3-7 seconds between queries
                await asyncio.sleep(random.uniform(3, 7))

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique_results: list[dict] = []
        for r in all_results:
            url = r.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(r)

        # Save assets
        saved = 0
        for r in unique_results:
            url = r.get("url", "")
            if not url:
                continue
            asset_id = await self.save_asset(
                target_id, "url", url, "dork_engine",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        return {"found": saved}

    async def _scrape_engine(self, engine: str, query: str) -> list[dict]:
        """Scrape a search engine for results.

        Each scraper dispatches to the appropriate engine-specific method.
        Returns list of {"url": ..., "title": ...} dicts.
        """
        scrapers = {
            "google": self._scrape_google,
            "bing": self._scrape_bing,
            "duckduckgo": self._scrape_duckduckgo,
        }
        scraper = scrapers.get(engine, self._scrape_duckduckgo)
        return await scraper(query)

    async def _scrape_google(self, query: str) -> list[dict]:
        """Scrape Google search results."""
        url = f"https://www.google.com/search?q={quote_plus(query)}&num=20"
        return await self._http_get_parse(url)

    async def _scrape_bing(self, query: str) -> list[dict]:
        """Scrape Bing search results."""
        url = f"https://www.bing.com/search?q={quote_plus(query)}&count=20"
        return await self._http_get_parse(url)

    async def _scrape_duckduckgo(self, query: str) -> list[dict]:
        """Scrape DuckDuckGo HTML search results."""
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        return await self._http_get_parse(url)

    async def _http_get_parse(self, url: str) -> list[dict]:
        """Fetch a URL and parse result links from HTML."""
        headers = {"User-Agent": random.choice(_USER_AGENTS)}
        results = []

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, allow_redirects=True) as resp:
                    if resp.status in (429, 503):
                        logger.info(f"Rate limited ({resp.status}), skipping")
                        return []
                    html = await resp.text()

            # Extract URLs from href attributes
            import re
            for match in re.finditer(r'href=["\']?(https?://[^"\'<>\s]+)', html):
                found_url = match.group(1)
                parsed = urlparse(found_url)
                # Filter out search engine URLs
                if parsed.hostname and not any(
                    se in parsed.hostname
                    for se in ("google.", "bing.", "duckduckgo.", "microsoft.", "yahoo.")
                ):
                    results.append({"url": found_url, "title": ""})
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"HTTP request failed: {e}")

        return results
