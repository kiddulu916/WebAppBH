# workers/info_gathering/tools/shodan_searcher.py
"""ShodanSearcher — optional Shodan API integration for host/port/service discovery."""

import asyncio
import os

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class ShodanSearcher(InfoGatheringTool):
    """Query Shodan API for host information, open ports, and service banners.

    Skips execution if SHODAN_API_KEY environment variable is not set.
    Rate limited to 1 request per second per Shodan free-tier requirements.
    """

    BASE_URL = "https://api.shodan.io"

    async def execute(self, target_id: int, **kwargs) -> dict | None:
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            logger.info("SHODAN_API_KEY not set, skipping Shodan search")
            return None

        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        saved = 0
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Resolve domain to IPs
                resolve_url = f"{self.BASE_URL}/dns/resolve?hostnames={domain}&key={api_key}"
                async with session.get(resolve_url) as resp:
                    if resp.status != 200:
                        return {"found": 0}
                    ip_data = await resp.json()

                for hostname, ip in ip_data.items():
                    if not ip:
                        continue

                    # Scope check the IP
                    if scope_manager and not await self.scope_check(target_id, ip, scope_manager):
                        continue

                    # Save IP as asset
                    asset_id = await self.save_asset(
                        target_id, "ip", ip, "shodan",
                        scope_manager=scope_manager,
                    )
                    if asset_id:
                        saved += 1

                    # Rate limit
                    await asyncio.sleep(1)

                    # Get host details
                    host_url = f"{self.BASE_URL}/shodan/host/{ip}?key={api_key}"
                    async with session.get(host_url) as host_resp:
                        if host_resp.status == 200:
                            host_data = await host_resp.json()
                            # Save port/service observations
                            if asset_id and host_data.get("ports"):
                                await self.save_observation(
                                    asset_id,
                                    tech_stack={
                                        "ports": host_data.get("ports", []),
                                        "os": host_data.get("os"),
                                        "org": host_data.get("org"),
                                        "isp": host_data.get("isp"),
                                    },
                                    headers={"shodan_data": {
                                        "vulns": host_data.get("vulns", []),
                                        "hostnames": host_data.get("hostnames", []),
                                    }},
                                )

                    await asyncio.sleep(1)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Shodan API request failed: {e}")

        return {"found": saved}
