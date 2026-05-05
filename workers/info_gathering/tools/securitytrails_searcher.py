# workers/info_gathering/tools/securitytrails_searcher.py
"""SecurityTrailsSearcher — optional SecurityTrails API for DNS history and associations."""

import asyncio
import os

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class SecurityTrailsSearcher(InfoGatheringTool):
    """Query SecurityTrails API for DNS records, subdomains, and domain associations.

    Skips execution if SECURITYTRAILS_API_KEY is not set.
    Rate limited to 2 seconds between API calls.
    """

    BASE_URL = "https://api.securitytrails.com/v1"

    async def execute(self, target_id: int, **kwargs) -> dict | None:
        api_key = os.environ.get("SECURITYTRAILS_API_KEY")
        if not api_key:
            logger.info("SECURITYTRAILS_API_KEY not set, skipping SecurityTrails search")
            return None

        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        headers = {"APIKEY": api_key, "Accept": "application/json"}
        saved = 0

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                # 1. Get domain DNS records
                dns_url = f"{self.BASE_URL}/domain/{domain}"
                async with session.get(dns_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Extract A records (IPs)
                        for record in data.get("current_dns", {}).get("a", {}).get("values", []):
                            ip = record.get("ip")
                            if ip:
                                aid = await self.save_asset(
                                    target_id, "ip", ip, "securitytrails",
                                    scope_manager=scope_manager,
                                )
                                if aid:
                                    saved += 1

                await asyncio.sleep(2)

                # 2. Get subdomains
                sub_url = f"{self.BASE_URL}/domain/{domain}/subdomains"
                async with session.get(sub_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            fqdn = f"{sub}.{domain}"
                            aid = await self.save_asset(
                                target_id, "subdomain", fqdn, "securitytrails",
                                scope_manager=scope_manager,
                            )
                            if aid:
                                saved += 1

                await asyncio.sleep(2)

                # 3. Historical DNS (A records)
                hist_url = f"{self.BASE_URL}/history/{domain}/dns/a"
                async with session.get(hist_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get("records", []):
                            for value in record.get("values", []):
                                ip = value.get("ip")
                                if ip:
                                    aid = await self.save_asset(
                                        target_id, "ip", ip, "securitytrails_history",
                                        scope_manager=scope_manager,
                                    )
                                    if aid:
                                        saved += 1

                await asyncio.sleep(2)

                # 4. Associated domains
                assoc_url = f"{self.BASE_URL}/domain/{domain}/associated"
                async with session.get(assoc_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get("records", []):
                            hostname = record.get("hostname")
                            if hostname and hostname != domain:
                                aid = await self.save_asset(
                                    target_id, "domain", hostname, "securitytrails_associated",
                                    scope_manager=scope_manager,
                                )
                                if aid:
                                    saved += 1

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"SecurityTrails API request failed: {e}")

        return {"found": saved}
