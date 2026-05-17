# workers/info_gathering/tools/vhost_prober.py
"""VHostProber wrapper — virtual host discovery."""

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool


class VHostProber(InfoGatheringTool):
    """Discover virtual hosts by probing with different Host headers."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        async with get_session() as session:
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "subdomain",
            )
            result = await session.execute(stmt)
            subdomains = [(row[0], row[1]) for row in result.all()]

        if len(subdomains) < 2:
            return

        base_url = f"https://{target.base_domain}"
        for sub_asset_id, subdomain in subdomains:
            try:
                async with aiohttp.ClientSession() as http_session:
                    headers = {"Host": subdomain}
                    async with http_session.get(
                        base_url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302, 403):
                            await self.save_observation(
                                asset_id=sub_asset_id,
                                tech_stack={"vhost": subdomain, "status": resp.status},
                            )
            except Exception:
                continue