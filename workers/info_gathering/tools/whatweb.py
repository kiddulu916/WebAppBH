# workers/info_gathering/tools/whatweb.py
"""WhatWeb wrapper — application-layer fingerprint for a single host.

Phase 2: returns a ``ProbeResult`` so the FingerprintAggregator can consume
plugin matches as ``app_fingerprint`` signals. Plugin → slot mapping is
fixed (server vendors → ``origin_server``, CDNs → ``edge``, app frameworks
→ ``framework``); unknown plugins are recorded in the Observation but do
not contribute signals.
"""
from __future__ import annotations

import json
from typing import Any

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage2-whatweb")

# whatweb plugin name → fingerprint slot.
_PLUGIN_SLOTS: dict[str, str] = {
    # origin servers
    "Apache":          "origin_server",
    "nginx":           "origin_server",
    "IIS":             "origin_server",
    "Tomcat":          "origin_server",
    "Caddy":           "origin_server",
    "lighttpd":        "origin_server",
    # edge / CDN
    "Cloudflare":      "edge",
    "Akamai":          "edge",
    "Fastly":          "edge",
    "CloudFront":      "edge",
    # frameworks
    "PHP":             "framework",
    "ASP.NET":         "framework",
    "Django":          "framework",
    "Ruby-on-Rails":   "framework",
    "Express":         "framework",
    "Laravel":         "framework",
    "Flask":           "framework",
}


class WhatWeb(InfoGatheringTool):
    """Application-layer fingerprint using WhatWeb."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return ProbeResult(
                probe="app_fingerprint", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        cmd = ["whatweb", "--json", "-"]
        if intensity == "high":
            cmd += ["-a", "3"]
        cmd.append(f"https://{host}")

        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
        except Exception as exc:
            logger.warning(
                "whatweb subprocess failed",
                extra={"host": host, "asset_id": asset_id, "error": str(exc)},
            )
            return ProbeResult(
                probe="app_fingerprint", obs_id=None, signals={}, error=str(exc),
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning(
                "whatweb stdout was not valid JSON",
                extra={"host": host, "asset_id": asset_id, "error": str(exc)},
            )
            return ProbeResult(
                probe="app_fingerprint", obs_id=None, signals={},
                error="invalid json from whatweb",
            )
        if not isinstance(data, list):
            logger.warning(
                "whatweb stdout was not a JSON list",
                extra={"host": host, "asset_id": asset_id, "type": type(data).__name__},
            )
            return ProbeResult(
                probe="app_fingerprint", obs_id=None, signals={},
                error="whatweb returned non-list",
            )
        if not data:
            return ProbeResult(probe="app_fingerprint", obs_id=None, signals={})

        entry = data[0]
        plugins = entry.get("plugins", {})
        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "app_fingerprint",
                "host": entry.get("target", ""),
                "plugins": plugins,
            },
        )

        signals: dict[str, Any] = {"origin_server": [], "edge": [], "framework": []}
        for plugin in plugins:
            slot = _PLUGIN_SLOTS.get(plugin)
            if slot is None:
                continue
            signals[slot].append({
                "src": "app_fingerprint", "value": plugin, "w": 0.5,
            })
        return ProbeResult(probe="app_fingerprint", obs_id=obs_id, signals=signals)
