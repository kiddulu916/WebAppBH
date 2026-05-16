# workers/info_gathering/tools/websocket_prober.py
"""WebSocketProber — detect WebSocket endpoints via active WS upgrade handshake."""

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

        confirmed = 0
        rejected = 0

        async with aiohttp.ClientSession() as http:
            for host, host_asset_id in hosts:
                for path in WS_PATHS:
                    url = f"https://{host}{path}"
                    await self.acquire_rate_limit(rate_limiter)
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
                        confirmed += 1
                    elif status in (400, 403):
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
                        rejected += 1

        return {"found": confirmed, "rejected": rejected}

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
        except Exception:
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
