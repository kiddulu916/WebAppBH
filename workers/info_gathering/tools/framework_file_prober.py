# workers/info_gathering/tools/framework_file_prober.py
"""FrameworkFileProber — framework-specific path probing (WSTG 4.1.8)."""
from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-framework-file-prober")

_ACCESSIBLE = frozenset({200, 301, 302, 403})
_CONCURRENCY = 5

# (path, slot, vendor, path_type)  path_type: "admin" | "info_file" | "indicator"
_PROBE_PATHS: list[tuple[str, str, str, str]] = [
    ("/wp-login.php",                        "cms",       "WordPress", "admin"),
    ("/readme.html",                         "cms",       "WordPress", "info_file"),
    ("/license.txt",                         "cms",       "WordPress", "info_file"),
    ("/wp-includes/js/jquery/jquery.min.js", "cms",       "WordPress", "indicator"),
    ("/administrator/index.php",             "cms",       "Joomla",    "admin"),
    ("/CHANGELOG.txt",                       "cms",       "Joomla",    "info_file"),
    ("/htaccess.txt",                        "cms",       "Joomla",    "info_file"),
    ("/core/CHANGELOG.txt",                  "cms",       "Drupal",    "info_file"),
    ("/artisan",                             "framework", "Laravel",   "indicator"),
    ("/.env",                                "framework", "Laravel",   "indicator"),
    ("/admin/login/?next=/admin/",           "framework", "Django",    "admin"),
    ("/rails/info/properties",               "framework", "Rails",     "indicator"),
]


class FrameworkFileProber(InfoGatheringTool):
    """Probes known framework-specific paths to confirm technology identity (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="framework_files", obs_id=None, signals={},
                               error="missing host or asset_id")

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        matched: list[dict[str, str]] = []
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def _probe(path: str, slot: str, vendor: str, path_type: str) -> None:
            try:
                async with sem:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{host}{path}",
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in _ACCESSIBLE:
                                matched.append({"path": path, "slot": slot,
                                                "vendor": vendor, "path_type": path_type,
                                                "status": str(resp.status)})
            except Exception as exc:
                logger.debug(
                    "framework_file_prober path probe failed",
                    host=host, path=path, error=str(exc),
                )

        await asyncio.gather(*[_probe(p, sl, v, pt) for p, sl, v, pt in _PROBE_PATHS])

        signals: dict[str, Any] = {"framework": [], "cms": [], "language": [],
                                   "_admin_paths": [], "_info_file_paths": []}
        for m in matched:
            signals[m["slot"]].append({
                "src": "framework_files", "value": m["vendor"],
                "w": 0.6, "path": m["path"], "path_type": m["path_type"],
            })
            if m["path_type"] == "admin":
                signals["_admin_paths"].append(m["path"])
            elif m["path_type"] == "info_file":
                signals["_info_file_paths"].append(m["path"])

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "framework_files", "host": host, "matched": matched},
        )
        return ProbeResult(probe="framework_files", obs_id=obs_id, signals=signals)
