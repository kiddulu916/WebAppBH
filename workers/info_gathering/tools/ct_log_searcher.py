# workers/info_gathering/tools/ct_log_searcher.py
"""CTLogSearcher — enumerate hostnames from Certificate Transparency logs via crt.sh."""

import asyncio

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class CTLogSearcher(InfoGatheringTool):
    """Query crt.sh to discover hostnames from Certificate Transparency logs.

    Surfaces hostnames that Amass folds into its internal output as first-class
    Asset rows, including old dev/staging domains no longer in DNS.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        scope_manager = kwargs.get("scope_manager")
        if not target:
            return {"found": 0}

        data = await self._fetch_crtsh(target.base_domain)
        hostnames = self._parse_hostnames(data, target.base_domain)

        saved = 0
        for hostname in hostnames:
            asset_id = await self.save_asset(
                target_id, "subdomain", hostname, "ct_log_searcher",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        return {"found": saved}

    async def _fetch_crtsh(self, domain: str) -> list:
        """GET crt.sh JSON API for the domain. Returns raw record list or []."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"Accept": "application/json"}) as resp:
                    if resp.status != 200:
                        logger.warning(
                            f"CTLogSearcher: crt.sh returned {resp.status} for {domain}"
                        )
                        return []
                    return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.warning(f"CTLogSearcher: request failed for {domain}: {type(exc).__name__}")
            return []
        except Exception as exc:
            logger.error(f"CTLogSearcher: unexpected error for {domain}: {type(exc).__name__}")
            return []

    def _parse_hostnames(self, data: list, domain: str) -> set[str]:
        """Extract unique in-scope hostnames from crt.sh records."""
        hostnames: set[str] = set()
        for record in data:
            for name in record.get("name_value", "").splitlines():
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                if name and (name.endswith(f".{domain}") or name == domain):
                    hostnames.add(name)
        return hostnames
