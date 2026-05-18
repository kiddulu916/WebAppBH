"""CDNProbe — CDN detection via response headers and ASN lookup (WSTG-INFO-10)."""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-cdn-probe")

# (header_lower, value_regex_or_None, provider)
_HEADER_SIGNATURES: list[tuple[str, str | None, str]] = [
    ("cf-ray",          None,            "cloudflare"),
    ("cf-cache-status", None,            "cloudflare"),
    ("x-served-by",     r"cache-",       "fastly"),
    ("fastly-restarts", None,            "fastly"),
    ("x-amz-cf-id",     None,            "cloudfront"),
    ("x-amz-cf-pop",    None,            "cloudfront"),
    ("x-azure-ref",     None,            "azure_cdn"),
    ("x-ms-ref",        None,            "azure_cdn"),
    ("x-sucuri-id",     None,            "sucuri"),
    ("x-sucuri-cache",  None,            "sucuri"),
    ("x-cache",         r"akamaitechnologies", "akamai"),
    ("server",          r"AkamaiGHost",  "akamai"),
    ("via",             r"(?i)akamai",   "akamai"),
]

# ASN org substrings → CDN provider
_ASN_SIGNATURES: list[tuple[str, str]] = [
    ("cloudflare", "cloudflare"),
    ("akamai",     "akamai"),
    ("fastly",     "fastly"),
    ("amazon",     "cloudfront"),
    ("sucuri",     "sucuri"),
    ("azure",      "azure_cdn"),
]


class CDNProbe(InfoGatheringTool):
    """Detects CDN providers via response headers and ASN lookup (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        provider: str | None = None
        signals: list[str] = []
        ips: list[str] = []

        async with aiohttp.ClientSession() as sess:
            # Phase 1: header-based detection
            try:
                async with sess.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
            except Exception as exc:
                logger.warning("cdn_probe header fetch failed", host=host, error=str(exc))
                headers = {}

            for hdr, pattern, cdn in _HEADER_SIGNATURES:
                val = headers.get(hdr)
                if val is None:
                    continue
                if pattern is None or re.search(pattern, val):
                    provider = cdn
                    signals.append(f"header:{hdr}")
                    break

            # Phase 2: ASN-based detection (only if headers inconclusive)
            if provider is None:
                try:
                    loop = asyncio.get_event_loop()
                    info = await loop.run_in_executor(None, socket.getaddrinfo, host, 80)
                    ips = list({entry[4][0] for entry in info})
                except Exception as exc:
                    logger.debug("cdn_probe DNS resolution failed", host=host, error=str(exc))

                for ip in ips[:2]:
                    try:
                        async with sess.get(
                            f"https://ipinfo.io/{ip}/org",
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            org = (await resp.text()).lower()
                        for asn_substr, cdn in _ASN_SIGNATURES:
                            if asn_substr in org:
                                provider = cdn
                                signals.append(f"asn:{org.strip()}")
                                break
                    except Exception as exc:
                        logger.debug("cdn_probe ASN lookup failed", ip=ip, error=str(exc))
                    if provider:
                        break

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "cdn_probe",
                "host": host,
                "detected": provider is not None,
                "provider": provider or "none",
                "signals": signals,
                "ips": ips,
            },
        )
