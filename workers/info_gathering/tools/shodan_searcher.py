# workers/info_gathering/tools/shodan_searcher.py
"""ShodanSearcher — optional OSINT enrichment via Shodan API (WSTG-INFO-01)."""

import os

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class ShodanSearcher(InfoGatheringTool):
    """Query Shodan for subdomains, IPs, and open ports.

    Skips gracefully when SHODAN_API_KEY is not configured.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            logger.info("ShodanSearcher skipped — no SHODAN_API_KEY configured")
            return {"skipped": True, "reason": "no_api_key"}

        domain = kwargs.get("domain")
        scope_manager = kwargs.get("scope_manager")

        if not domain:
            target = kwargs.get("target")
            if target:
                domain = getattr(target, "base_domain", None)
            if not domain:
                return {"found": 0}

        from lib_webbh.intel_enrichment import enrich_shodan

        rate_limiter = kwargs.get("rate_limiter")
        await self.acquire_rate_limit(rate_limiter)
        result = await enrich_shodan(domain, api_key=api_key)

        saved = 0

        # Save discovered subdomains
        for fqdn in result.subdomains:
            asset_id = await self.save_asset(
                target_id, "subdomain", fqdn, "shodan",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        # Save discovered IPs
        for ip in result.ips:
            asset_id = await self.save_asset(
                target_id, "ip", ip, "shodan",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        # Save port/service observations linked to IP assets
        for port_info in result.ports:
            ip = port_info.get("ip", "")
            if not ip:
                continue
            asset_id = await self.save_asset(
                target_id, "ip", ip, "shodan",
                scope_manager=scope_manager,
            )
            if asset_id:
                await self.save_observation(
                    asset_id,
                    tech_stack={
                        "port": port_info.get("port"),
                        "service": port_info.get("service"),
                        "source": "shodan",
                    },
                )

        return {"found": saved}
