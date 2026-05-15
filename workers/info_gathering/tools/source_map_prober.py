# workers/info_gathering/tools/source_map_prober.py
"""SourceMapProber — detect exposed source map files (WSTG-INFO-05)."""
import re

import aiohttp
from sqlalchemy import or_, select

from lib_webbh import Asset, Observation, get_session
from workers.info_gathering.base_tool import InfoGatheringTool


class SourceMapProber(InfoGatheringTool):
    """Check whether .map files are publicly accessible for discovered JS/CSS assets."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        candidates = await self._get_candidates(target_id)
        if not candidates:
            candidates = await self._candidates_from_root(target.base_domain, target_id)

        for url, asset_id in candidates:
            map_url = f"{url}.map"
            if not await self._probe_map(map_url):
                continue
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={"_source": "source_map_prober", "map_url": map_url},
            )
            await self.save_vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity="medium",
                title=f"Source map file exposed: {map_url}",
                description=(
                    f"The source map at {map_url} is publicly accessible. "
                    "This reveals original (unminified) source code, file paths, "
                    "and internal application structure to attackers."
                ),
                source_tool="source_map_prober",
                section_id="4.1.5",
                vuln_type="source_map_exposure",
                evidence={"map_url": map_url, "js_url": url},
            )

    async def _get_candidates(self, target_id: int) -> list[tuple[str, int]]:
        """Return (url, asset_id) pairs for .js/.css assets not yet probed."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value, Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                    or_(
                        Asset.asset_value.like("%.js"),
                        Asset.asset_value.like("%.css"),
                    ),
                )
            )
            result = await session.execute(stmt)
            all_assets = result.all()
            if not all_assets:
                return []

            asset_ids = [row[1] for row in all_assets]
            processed_stmt = (
                select(Observation.asset_id)
                .where(
                    Observation.asset_id.in_(asset_ids),
                    Observation.tech_stack["_source"].astext == "source_map_prober",
                )
            )
            processed_result = await session.execute(processed_stmt)
            processed_ids = {row[0] for row in processed_result.all()}

            return [(url, aid) for url, aid in all_assets if aid not in processed_ids]

    async def _candidates_from_root(self, base_domain: str, target_id: int) -> list[tuple[str, int]]:
        """Parse root page HTML for .js/.css links; create Asset records."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://{base_domain}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
        except Exception as exc:
            self.log.debug("source_map_prober fallback fetch failed", error=str(exc))
            return []

        found = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
        found += re.findall(r'<link[^>]+href=["\']([^"\']+\.css)["\']', html)

        results = []
        for href in found:
            if href.startswith("http"):
                full_url = href
            elif href.startswith("//"):
                full_url = "https:" + href
            elif href.startswith("/"):
                full_url = f"https://{base_domain}{href}"
            else:
                full_url = f"https://{base_domain}/{href}"
            aid = await self.save_asset(target_id, "url", full_url, "source_map_prober")
            if aid is None:
                async with get_session() as session:
                    stmt = select(Asset.id).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == full_url,
                    )
                    r = await session.execute(stmt)
                    aid = r.scalar_one_or_none()
            if aid:
                results.append((full_url, aid))
        return results

    async def _probe_map(self, map_url: str) -> bool:
        """Return True if the .map URL responds HTTP 200."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.head(map_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return True
                    if resp.status not in (405, 501):
                        return False
                # HEAD not supported — fall back to GET
                async with http.get(
                    map_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False
