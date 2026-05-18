"""ReverseProxyProbe — reverse proxy detection via header analysis (WSTG-INFO-10)."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-reverse-proxy-probe")

# Explicit proxy-identifying headers: (header_lower, value_regex_or_None, proxy_type)
_EXPLICIT_HEADERS: list[tuple[str, str | None, str]] = [
    ("x-varnish",          None,       "varnish"),
    ("x-cache",            r"(?i)hit", "generic_cache"),
    ("x-cache-hits",       None,       "generic_cache"),
    ("x-drupal-cache",     None,       "drupal_cache"),
    ("x-squid-error",      None,       "squid"),
    ("x-forwarded-server", None,       "generic_proxy"),
]

# Headers whose mere presence indicates a proxy layer
_PRESENCE_HEADERS: list[str] = [
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
]


class ReverseProxyProbe(InfoGatheringTool):
    """Detects reverse proxy layers via response header analysis (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        proxy_type: str | None = None
        signals: list[str] = []

        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("reverse_proxy_probe fetch failed", host=host, error=str(exc))
            headers = {}

        # Check explicit proxy headers
        for hdr, pattern, ptype in _EXPLICIT_HEADERS:
            val = headers.get(hdr)
            if val is None:
                continue
            if pattern is None or re.search(pattern, val):
                if proxy_type is None:
                    proxy_type = ptype
                signals.append(hdr)

        # Via header — any value indicates a proxy chain
        via = headers.get("via")
        if via:
            signals.append("via")
            if proxy_type is None:
                proxy_type = "generic_proxy"

        # Forwarding headers — presence alone indicates proxying
        for hdr in _PRESENCE_HEADERS:
            if hdr in headers:
                signals.append(hdr)
                if proxy_type is None:
                    proxy_type = "generic_proxy"

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "reverse_proxy_probe",
                "host": host,
                "detected": proxy_type is not None,
                "proxy_type": proxy_type or "none",
                "signals": signals,
            },
        )
