# workers/info_gathering/tools/header_framework_probe.py
"""HeaderFrameworkProbe — framework fingerprinting via HTTP response headers (WSTG 4.1.8)."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-header-framework-probe")

# (header_lower, value_regex_or_None, slot, vendor, use_full_value_as_version, weight)
# use_full_value_as_version=True: the entire header value IS the version (e.g. X-AspNetMvc-Version).
# value_regex: must match; group 1 (if present) extracts version.
_HEADER_SIGNATURES: list[tuple[str, str | None, str, str, bool, float]] = [
    ("x-aspnetmvc-version", None,                          "framework", "ASP.NET MVC", True,  0.7),
    ("x-aspnet-version",    None,                          "language",  ".NET",        True,  0.6),
    ("x-generator",         r"(?i)drupal\s*([\d.]+)?",     "cms",       "Drupal",      False, 0.8),
    ("x-generator",         r"(?i)joomla",                 "cms",       "Joomla",      False, 0.7),
    ("x-generator",         r"(?i)wordpress\s*([\d.]+)?",  "cms",       "WordPress",   False, 0.7),
    ("x-powered-by",        r"(?i)php/([\d.]+)",           "language",  "PHP",         False, 0.6),
    ("x-powered-by",        r"(?i)express",                "framework", "Express",     False, 0.5),
    ("x-powered-by",        r"(?i)asp\.net",               "language",  "ASP.NET",     False, 0.5),
    ("x-pingback",          r"/xmlrpc\.php",               "cms",       "WordPress",   False, 0.5),
    ("x-drupal-cache",      None,                          "cms",       "Drupal",      False, 0.4),
    ("x-drupal-dynamic-cache", None,                       "cms",       "Drupal",      False, 0.4),
]


class HeaderFrameworkProbe(InfoGatheringTool):
    """Passive framework fingerprinting via HTTP response headers (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="header_framework", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            await self.acquire_rate_limit(kwargs.get("rate_limiter"))
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("header_framework_probe failed",
                           extra={"host": host, "error": str(exc)})
            return ProbeResult(probe="header_framework", obs_id=None, signals={}, error=str(exc))

        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        raw_headers: dict[str, str] = {}

        for hdr, val_pattern, slot, vendor, use_full, weight in _HEADER_SIGNATURES:
            hdr_value = headers.get(hdr)
            if hdr_value is None:
                continue
            raw_headers[hdr] = hdr_value
            version: str | None = None
            if val_pattern is not None:
                m = re.search(val_pattern, hdr_value)
                if not m:
                    continue
                if m.lastindex and m.lastindex >= 1:
                    version = m.group(1) or None
            elif use_full:
                version = hdr_value.strip()
            sig: dict[str, Any] = {"src": "header_framework", "value": vendor, "w": weight}
            if version:
                sig["version"] = version
            signals[slot].append(sig)

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "header_framework", "host": host, "headers": raw_headers},
        )
        return ProbeResult(probe="header_framework", obs_id=obs_id, signals=signals)
