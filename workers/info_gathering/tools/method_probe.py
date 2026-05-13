# workers/info_gathering/tools/method_probe.py
"""MethodProbe — HTTP method behavior probing, intensity-gated.

Sends a small set of HTTP methods against the host's ``/`` and records
status, Allow, Server. Higher intensities add successively riskier verbs:

- low:    OPTIONS, HEAD, lowercase get
- medium: + PROPFIND, TRACE
- high:   + ASDF (garbage), DELETE, PUT

Issues an ``Allow``-header-based hint for IIS (PROPFIND listed → 0.2 weight
into ``origin_server``).
"""
from __future__ import annotations

from typing import Any

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

LOW_METHODS: list[str] = ["OPTIONS", "HEAD", "get"]
MED_METHODS: list[str] = ["PROPFIND", "TRACE"]
HIGH_METHODS: list[str] = ["ASDF", "DELETE", "PUT"]


class MethodProbe(InfoGatheringTool):
    """Stage 2 HTTP method behavior probe."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return ProbeResult(
                probe="method_probe", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        methods = list(LOW_METHODS)
        if intensity in ("medium", "high"):
            methods += MED_METHODS
        if intensity == "high":
            methods += HIGH_METHODS

        rate_limiter = kwargs.get("rate_limiter")
        url = f"https://{host}/"
        results: dict[str, dict[str, Any]] = {}
        try:
            async with aiohttp.ClientSession() as session:
                for method in methods:
                    await self.acquire_rate_limit(rate_limiter)
                    results[method] = await self._send_method(session, method, url)
        except Exception as exc:
            return ProbeResult(
                probe="method_probe", obs_id=None, signals={}, error=str(exc),
            )

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "method_options",
                "results": results,
                "intensity": intensity,
            },
        )

        signals: dict[str, Any] = {"origin_server": []}
        allow = results.get("OPTIONS", {}).get("allow", "") or ""
        if "PROPFIND" in allow.upper():
            signals["origin_server"].append(
                {"src": "method_options", "value": "IIS", "w": 0.2},
            )

        return ProbeResult(probe="method_probe", obs_id=obs_id, signals=signals)

    async def _send_method(
        self, session: aiohttp.ClientSession, method: str, url: str,
    ) -> dict[str, Any]:
        try:
            async with session.request(
                method.upper(), url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
            ) as resp:
                body = await resp.read()
                return {
                    "status": resp.status,
                    "body_len": len(body),
                    "allow": resp.headers.get("Allow", ""),
                    "server": resp.headers.get("Server", ""),
                }
        except Exception as exc:
            return {"error": str(exc)}
