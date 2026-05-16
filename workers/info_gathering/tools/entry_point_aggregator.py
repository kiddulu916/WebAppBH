# workers/info_gathering/tools/entry_point_aggregator.py
"""EntryPointAggregator — per-endpoint response header capture + parameter consolidation."""

from urllib.parse import parse_qsl, urlparse

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, Parameter, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger

_CUSTOM_PREFIXES = ("x-", "cf-")
_NAMED_HEADERS = frozenset({"server", "content-type", "allow", "www-authenticate"})


class EntryPointAggregator(InfoGatheringTool):
    """Fetch every discovered url/form endpoint; record headers + consolidate params."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        rate_limiter = kwargs.get("rate_limiter")

        async with get_session() as session:
            assets = (await session.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["url", "form"]),
                )
            )).scalars().all()

        obs_count = 0
        param_count = 0

        async with aiohttp.ClientSession() as http:
            for asset in assets:
                await self.acquire_rate_limit(rate_limiter)
                obs_data = await self._capture_headers(http, asset.asset_value)
                if obs_data:
                    await self.save_observation(
                        asset_id=asset.id,
                        tech_stack=obs_data,
                        status_code=obs_data.get("status_code"),
                    )
                    obs_count += 1
                if asset.source_tool == "paramspider":
                    written = await self._consolidate_query_params(asset)
                    param_count += written

        return {"found": obs_count, "parameters": param_count}

    async def _capture_headers(
        self, session: aiohttp.ClientSession, url: str,
    ) -> dict | None:
        for method_name in ("head", "get"):
            try:
                method = getattr(session, method_name)
                async with method(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    if method_name == "head" and resp.status == 405:
                        continue
                    return self._extract_header_data(resp)
            except Exception:
                continue
        logger.warning(f"EntryPointAggregator: could not fetch {url}")
        return None

    def _extract_header_data(self, resp) -> dict:
        headers = resp.headers
        custom = {
            k: v for k, v in headers.items()
            if k.lower().startswith(_CUSTOM_PREFIXES)
            or k.lower() in _NAMED_HEADERS
        }
        cookies = list(headers.getall("Set-Cookie", []))
        auth_required = (
            resp.status in (401, 403)
            or "www-authenticate" in {k.lower() for k in headers}
        )
        allow = headers.get("Allow", "")
        methods = [m.strip() for m in allow.split(",")] if allow else []
        return {
            "_probe": "entry_point_aggregator",
            "custom_headers": custom,
            "set_cookie": cookies,
            "auth_required": auth_required,
            "methods_allowed": methods,
            "status_code": resp.status,
        }

    async def _consolidate_query_params(self, asset: Asset) -> int:
        params = parse_qsl(urlparse(asset.asset_value).query, keep_blank_values=True)
        if not params:
            return 0
        written = 0
        async with get_session() as session:
            for name, value in params:
                existing = (await session.execute(
                    select(Parameter).where(
                        Parameter.asset_id == asset.id,
                        Parameter.param_name == name,
                    )
                )).scalar_one_or_none()
                if existing is not None:
                    continue
                session.add(Parameter(
                    asset_id=asset.id,
                    param_name=name,
                    param_value=value or None,
                    source_url=asset.asset_value,
                ))
                written += 1
            await session.commit()
        return written
