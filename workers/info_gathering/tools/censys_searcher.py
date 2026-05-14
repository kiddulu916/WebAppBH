# workers/info_gathering/tools/censys_searcher.py
"""CensysSearcher — optional OSINT enrichment via Censys API (WSTG-INFO-01)."""

import asyncio
import os

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger

CENSYS_HOSTS_BASE = "https://search.censys.io/api/v2"


class CensysSearcher(InfoGatheringTool):
    """Query Censys for hosts, services, and TLS certificate SANs.

    Skips gracefully when CENSYS_API_SECRET is not configured.
    CENSYS_API_ID (Organization ID) is optional; used as the Basic Auth username when present.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        api_id = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")

        if not api_secret:
            logger.info("CensysSearcher skipped — no CENSYS_API_SECRET configured")
            return {"skipped": True, "reason": "no_api_key"}

        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")
        rate_limiter = kwargs.get("rate_limiter")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        auth = aiohttp.BasicAuth(api_id, api_secret)
        saved = 0

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(auth=auth, timeout=timeout) as session:
                # Search for hosts matching the domain
                search_url = f"{CENSYS_HOSTS_BASE}/hosts/search"
                params = {"q": domain, "per_page": 50}

                async with session.get(search_url, params=params) as resp:
                    if resp.status != 200:
                        logger.warning(f"Censys search returned {resp.status}")
                        return {"found": 0}
                    data = await resp.json()

                hits = data.get("result", {}).get("hits", [])

                for hit in hits:
                    ip = hit.get("ip", "")
                    if not ip:
                        continue

                    # Save IP as asset
                    asset_id = await self.save_asset(
                        target_id, "ip", ip, "censys",
                        scope_manager=scope_manager,
                    )
                    if asset_id:
                        saved += 1

                    # Save services as observations
                    services = hit.get("services", [])
                    if asset_id and services:
                        await self.save_observation(
                            asset_id,
                            tech_stack={
                                "services": [
                                    {
                                        "port": svc.get("port"),
                                        "service_name": svc.get("service_name"),
                                        "transport_protocol": svc.get("transport_protocol"),
                                    }
                                    for svc in services
                                ],
                                "source": "censys",
                            },
                        )

                    # Extract TLS SANs -> save as subdomains
                    for svc in services:
                        tls = svc.get("tls", {})
                        cert = tls.get("certificates", {}).get("leaf", {}).get("parsed", {})
                        names = cert.get("names", [])
                        for name in names:
                            name = name.lstrip("*.")
                            if name and domain in name:
                                san_id = await self.save_asset(
                                    target_id, "subdomain", name, "censys",
                                    scope_manager=scope_manager,
                                )
                                if san_id:
                                    saved += 1

                    await self.acquire_rate_limit(rate_limiter)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Censys request failed: {e}")

        return {"found": saved}
