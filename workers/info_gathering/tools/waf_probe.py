# workers/info_gathering/tools/waf_probe.py
"""WAFProbe — passive header/cookie detection plus intensity-gated ``wafw00f``.

Always runs the passive matcher (cheap GET + ``WAF_PASSIVE_PATTERNS`` lookup).
At ``intensity`` medium/high it additionally shells out to ``wafw00f`` for
active fingerprinting and emits the higher-weight ``waf_active`` signal.
"""
from __future__ import annotations

import json
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.fingerprint_signatures import WAF_PASSIVE_PATTERNS

logger = setup_logger("stage2-waf")


class WAFProbe(InfoGatheringTool):
    """Stage 2 WAF/CDN detection."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return ProbeResult(
                probe="waf", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        rate_limiter = kwargs.get("rate_limiter")
        passive: dict[str, Any] | None = None
        try:
            await self.acquire_rate_limit(rate_limiter)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}/",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    passive = self._passive_detect(resp)
        except Exception as exc:
            return ProbeResult(probe="waf", obs_id=None, signals={}, error=str(exc))

        active: dict[str, Any] | None = None
        if intensity in ("medium", "high"):
            # wafw00f itself issues several HTTP requests; passing the
            # rate_limiter to run_subprocess only meters the wrapper call.
            # We accept that as the price of a single rate-budget unit per
            # WAF probe invocation — wafw00f's internal requests bypass our
            # limiter.
            try:
                stdout = await self.run_subprocess(
                    ["wafw00f", "-a", "-o", "-", "-f", "json", f"https://{host}/"],
                    rate_limiter=rate_limiter,
                )
                parsed = json.loads(stdout) if stdout.strip() else {}
                # wafw00f returns either a single dict or a list of dicts.
                if isinstance(parsed, list) and parsed:
                    parsed = parsed[0]
                if isinstance(parsed, dict) and parsed.get("detected"):
                    active = {"vendor": parsed.get("firewall")}
            except Exception as exc:
                logger.warning(
                    "wafw00f active probe failed",
                    extra={"host": host, "asset_id": asset_id, "error": str(exc)},
                )
                active = None

        signals: dict[str, Any] = {"waf": []}
        if passive:
            for vendor in passive["vendors"]:
                signals["waf"].append(
                    {"src": "waf_passive", "value": vendor, "w": 0.4},
                )
        if active and active.get("vendor"):
            signals["waf"].append(
                {"src": "waf_active", "value": active["vendor"], "w": 0.9},
            )

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "waf",
                "passive": passive,
                "active": active,
                "intensity": intensity,
            },
        )
        return ProbeResult(probe="waf", obs_id=obs_id, signals=signals)

    def _passive_detect(self, resp: aiohttp.ClientResponse) -> dict[str, Any]:
        """Match response headers + Set-Cookie names against WAF_PASSIVE_PATTERNS."""
        vendors: list[str] = []
        evidence: list[str] = []
        header_keys = " ".join(resp.headers.keys()).lower()
        cookie_blob = " ".join(resp.headers.getall("Set-Cookie", [])).lower()
        for vendor, patterns in WAF_PASSIVE_PATTERNS.items():
            if any(h.lower() in header_keys for h in patterns["headers"]):
                vendors.append(vendor)
                evidence.append(f"header({vendor})")
                continue
            if any(c.lower() in cookie_blob for c in patterns["cookies"]):
                vendors.append(vendor)
                evidence.append(f"cookie({vendor})")
        return {"vendors": vendors, "evidence": evidence}
