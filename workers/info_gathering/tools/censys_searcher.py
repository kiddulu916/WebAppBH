# workers/info_gathering/tools/censys_searcher.py
"""CensysSearcher — optional Censys API integration for infrastructure and TLS discovery."""

import asyncio
import base64
import os

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class CensysSearcher(InfoGatheringTool):
    """Query Censys API for host infrastructure and TLS certificate information.

    Skips execution if CENSYS_API_ID or CENSYS_API_SECRET are not set.
    Rate limited to 0.5 seconds between API calls.
    """

    BASE_URL = "https://search.censys.io/api"

    async def execute(self, target_id: int, **kwargs) -> dict | None:
        api_id = os.environ.get("CENSYS_API_ID")
        api_secret = os.environ.get("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            logger.info("CENSYS_API_ID/SECRET not set, skipping Censys search")
            return None

        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}

        saved = 0
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                # Search for hosts associated with domain
                search_url = f"{self.BASE_URL}/v2/hosts/search"
                payload = {"q": domain, "per_page": 25}

                async with session.get(search_url, params=payload) as resp:
                    if resp.status != 200:
                        return {"found": 0}
                    data = await resp.json()

                hits = data.get("result", {}).get("hits", [])
                for hit in hits:
                    ip = hit.get("ip")
                    if not ip:
                        continue

                    asset_id = await self.save_asset(
                        target_id, "ip", ip, "censys",
                        scope_manager=scope_manager,
                    )
                    if asset_id:
                        saved += 1
                        # Save service and TLS info as observation
                        services = hit.get("services", [])
                        tls_names = []
                        ports = []
                        for svc in services:
                            ports.append(svc.get("port"))
                            tls = svc.get("tls", {})
                            certs = tls.get("certificates", {})
                            leaf = certs.get("leaf", {})
                            names = leaf.get("names", [])
                            tls_names.extend(names)

                        await self.save_observation(
                            asset_id,
                            tech_stack={
                                "ports": ports,
                                "tls_names": list(set(tls_names)),
                                "autonomous_system": hit.get("autonomous_system", {}),
                            },
                        )

                    await asyncio.sleep(0.5)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Censys API request failed: {e}")

        return {"found": saved}
