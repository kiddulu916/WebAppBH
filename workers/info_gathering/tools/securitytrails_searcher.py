# workers/info_gathering/tools/securitytrails_searcher.py
"""SecurityTrailsSearcher — optional OSINT enrichment via SecurityTrails API (WSTG-INFO-01)."""

import asyncio
import os

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger

SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"


class SecurityTrailsSearcher(InfoGatheringTool):
    """Query SecurityTrails for subdomains, DNS records, history, and associated domains.

    Skips gracefully when SECURITYTRAILS_API_KEY is not configured.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        if not api_key:
            logger.info("SecurityTrailsSearcher skipped — no SECURITYTRAILS_API_KEY configured")
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

        headers = {"APIKEY": api_key, "Accept": "application/json"}
        saved = 0

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:

                # 1. Subdomains
                async with session.get(f"{SECURITYTRAILS_BASE}/domain/{domain}/subdomains") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            fqdn = f"{sub}.{domain}"
                            asset_id = await self.save_asset(
                                target_id, "subdomain", fqdn, "securitytrails",
                                scope_manager=scope_manager,
                            )
                            if asset_id:
                                saved += 1

                await self.acquire_rate_limit(rate_limiter)

                # 2. DNS records (A records -> IPs)
                async with session.get(f"{SECURITYTRAILS_BASE}/domain/{domain}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        a_records = (
                            data
                            .get("current_dns", {})
                            .get("a", {})
                            .get("values", [])
                        )
                        for rec in a_records:
                            ip = rec.get("ip", "")
                            if ip:
                                asset_id = await self.save_asset(
                                    target_id, "ip", ip, "securitytrails",
                                    scope_manager=scope_manager,
                                )
                                if asset_id:
                                    saved += 1

                await self.acquire_rate_limit(rate_limiter)

                # 3. Historical DNS (A records) -- discover past IPs
                async with session.get(f"{SECURITYTRAILS_BASE}/history/{domain}/dns/a") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get("records", []):
                            for val in record.get("values", []):
                                ip = val.get("ip", "")
                                if ip:
                                    asset_id = await self.save_asset(
                                        target_id, "ip", ip, "securitytrails",
                                        scope_manager=scope_manager,
                                    )
                                    if asset_id:
                                        saved += 1

                await self.acquire_rate_limit(rate_limiter)

                # 4. Associated domains
                async with session.get(f"{SECURITYTRAILS_BASE}/domain/{domain}/associated") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get("records", []):
                            assoc_domain = record.get("hostname", "")
                            if assoc_domain and assoc_domain != domain:
                                asset_id = await self.save_asset(
                                    target_id, "domain", assoc_domain, "securitytrails",
                                    scope_manager=scope_manager,
                                )
                                if asset_id:
                                    saved += 1

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"SecurityTrails request failed: {e}")

        return {"found": saved}
