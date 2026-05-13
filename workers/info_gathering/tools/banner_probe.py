# workers/info_gathering/tools/banner_probe.py
"""BannerProbe — Stage 2 banner inspection via a single aiohttp GET /.

Reads ``Server`` / ``X-Powered-By`` headers and Set-Cookie values for passive
WAF hints. Emits per-slot signals (``edge``, ``origin_server``, ``framework``)
plus a ``_raw`` blob the aggregator consumes for info-leak Vulnerabilities.
"""
from __future__ import annotations

from typing import Any

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.fingerprint_signatures import WAF_PASSIVE_PATTERNS

# Cap per-value header length so a misbehaving proxy can't bloat the JSON
# column with a single multi-MB header value.
_MAX_HEADER_VALUE_LEN = 4096


def _truncate_headers(headers: dict[str, str]) -> dict[str, str]:
    """Truncate any header value longer than ``_MAX_HEADER_VALUE_LEN``."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        if len(v) > _MAX_HEADER_VALUE_LEN:
            out[k] = v[:_MAX_HEADER_VALUE_LEN] + "...[truncated]"
        else:
            out[k] = v
    return out

# Server-header substring → CDN vendor (edge slot).
_EDGE_KEYWORDS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "cloudfront": "CloudFront",
    "akamai": "Akamai",
    "fastly": "Fastly",
}

# Server-header substring → origin server vendor (origin_server slot).
_ORIGIN_KEYWORDS: dict[str, str] = {
    "apache": "Apache",
    "nginx": "nginx",
    "microsoft-iis": "IIS",
    "caddy": "Caddy",
    "lighttpd": "lighttpd",
    "tomcat": "Tomcat",
}


class BannerProbe(InfoGatheringTool):
    """Stage 2 banner probe — one HTTP GET, no subprocess."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(
                probe="banner", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        rate_limiter = kwargs.get("rate_limiter")
        url = f"https://{host}/"
        try:
            await self.acquire_rate_limit(rate_limiter)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=False,
                ) as resp:
                    headers = dict(resp.headers)
                    status = resp.status
                    cookies = resp.headers.getall("Set-Cookie", [])
        except Exception as exc:
            return ProbeResult(probe="banner", obs_id=None, signals={}, error=str(exc))

        server = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")
        signals: dict[str, Any] = {"edge": [], "origin_server": [], "framework": []}

        server_lower = server.lower()
        edge_hit = False
        for kw, vendor in _EDGE_KEYWORDS.items():
            if kw in server_lower:
                signals["edge"].append({"src": "banner.server", "value": vendor, "w": 0.6})
                edge_hit = True
                break
        if not edge_hit:
            for kw, vendor in _ORIGIN_KEYWORDS.items():
                if kw in server_lower:
                    signals["origin_server"].append(
                        {"src": "banner.server", "value": vendor, "w": 0.6},
                    )
                    break

        if x_powered_by:
            signals["framework"].append(
                {"src": "banner.x_powered_by", "value": x_powered_by, "w": 0.6},
            )

        cookie_blob = " ".join(cookies).lower()
        for vendor, patterns in WAF_PASSIVE_PATTERNS.items():
            if any(p.lower() in cookie_blob for p in patterns["cookies"]):
                signals["edge"].append(
                    {"src": "banner.cookie", "value": vendor, "w": 0.4},
                )

        headers_capped = _truncate_headers(headers)
        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "banner",
                "server_raw": server,
                "x_powered_by": x_powered_by,
            },
            status_code=status,
            headers=headers_capped,
        )
        signals["_raw"] = {
            "obs_id": obs_id,
            "server": server,
            "x_powered_by": x_powered_by,
            "headers": headers_capped,
        }
        return ProbeResult(probe="banner", obs_id=obs_id, signals=signals)
