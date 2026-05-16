# workers/info_gathering/tools/websocket_prober.py
"""WebSocketProber — detect WebSocket endpoints via active WS upgrade handshake."""

import asyncio
import base64
import os

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger

WS_PATHS = [
    "/ws", "/socket", "/websocket", "/socket.io",
    "/chat", "/live", "/stream", "/events",
    "/updates", "/notify", "/push", "/realtime", "/feed",
]


def _ws_upgrade_headers() -> dict[str, str]:
    key = base64.b64encode(os.urandom(16)).decode()
    return {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
    }


class WebSocketProber(InfoGatheringTool):
    """Probe base domain and all discovered subdomains for WebSocket endpoints."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or not asset_id:
            return {"found": 0, "rejected": 0}

        rate_limiter = kwargs.get("rate_limiter")
        scope_manager = kwargs.get("scope_manager")

        async with get_session() as session:
            rows = (await session.execute(
                select(Asset.asset_value, Asset.id).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["subdomain", "domain"]),
                )
            )).all()

        hosts = [(target.base_domain, asset_id)] + [
            (row[0], row[1]) for row in rows
            if row[0] != target.base_domain
        ]

        if scope_manager:
            hosts = [
                (host, hid) for host, hid in hosts
                if await self.scope_check(target_id, host, scope_manager)
            ]

        async with aiohttp.ClientSession() as http:
            tasks = [
                self._probe_host_path(http, target_id, host, host_asset_id, path, rate_limiter)
                for host, host_asset_id in hosts
                for path in WS_PATHS
            ]
            results = await asyncio.gather(*tasks)

        confirmed = sum(r[0] for r in results)
        rejected = sum(r[1] for r in results)
        return {"found": confirmed, "rejected": rejected}

    async def _probe_host_path(
        self,
        http: aiohttp.ClientSession,
        target_id: int,
        host: str,
        host_asset_id: int,
        path: str,
        rate_limiter,
    ) -> tuple[int, int]:
        """Probe a single host/path via HTTPS with HTTP fallback. Returns (confirmed, rejected)."""
        await self.acquire_rate_limit(rate_limiter)
        url = f"https://{host}{path}"
        status, accepted = await self._probe(http, url)

        if status == 0:
            # HTTPS unreachable — try plain HTTP for hosts that don't terminate TLS
            await self.acquire_rate_limit(rate_limiter)
            url = f"http://{host}{path}"
            status, accepted = await self._probe(http, url)

        if accepted:
            ws_asset_id = await self.save_asset(
                target_id, "websocket", url, "websocket_prober",
            )
            if ws_asset_id is None:
                ws_asset_id = await self._lookup_asset_id(target_id, url)
            if ws_asset_id:
                await self.save_observation(
                    asset_id=ws_asset_id,
                    tech_stack={
                        "_probe": "websocket_prober",
                        "status": 101,
                        "host": host,
                        "path": path,
                        "upgrade_accepted": True,
                    },
                )
            return (1, 0)

        if status in (400, 403):
            await self.save_observation(
                asset_id=host_asset_id,
                tech_stack={
                    "_probe": "websocket_prober",
                    "status": status,
                    "host": host,
                    "path": path,
                    "upgrade_rejected": True,
                },
            )
            return (0, 1)

        return (0, 0)

    async def _probe(
        self, session: aiohttp.ClientSession, url: str,
    ) -> tuple[int, bool]:
        try:
            async with session.get(
                url,
                headers=_ws_upgrade_headers(),
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
            ) as resp:
                return resp.status, resp.status == 101
        except Exception as exc:
            logger.warning(f"WebSocketProber probe failed for {url}: {exc}")
            return 0, False

    async def _lookup_asset_id(self, target_id: int, url: str) -> int | None:
        async with get_session() as session:
            row = (await session.execute(
                select(Asset.id).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == url,
                    Asset.asset_type == "websocket",
                )
            )).first()
            return row[0] if row else None
