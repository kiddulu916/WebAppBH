"""LoadBalancerProbe — load balancer detection via cookies and header variance (WSTG-INFO-10)."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-load-balancer-probe")

_PROBE_COUNT = 5

# (cookie_name_regex, vendor)
_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    (r"^BIGipServer",  "f5"),
    (r"^AWSALB$",      "aws_alb"),
    (r"^AWSALBCORS$",  "aws_alb"),
    (r"^TS[0-9a-f]+$", "f5_apm"),
    (r"^NSC_",         "netscaler"),
    (r"^visid_incap_", "incapsula"),
    (r"^incap_ses_",   "incapsula"),
]


def _detect_cookie_vendor(cookie_str: str) -> str | None:
    name = cookie_str.split("=")[0].strip()
    for pattern, vendor in _COOKIE_SIGNATURES:
        if re.match(pattern, name):
            return vendor
    return None


class LoadBalancerProbe(InfoGatheringTool):
    """Detects load balancers via LB-specific cookies and header variance (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        vendor: str | None = None
        signals: list[str] = []
        served_by_values: list[str] = []

        try:
            async with aiohttp.ClientSession() as sess:
                for _ in range(_PROBE_COUNT):
                    async with sess.request(
                        "HEAD", f"https://{host}",
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as resp:
                        # Cookie-based detection
                        if vendor is None:
                            for cookie in resp.headers.getall("set-cookie", []):
                                detected = _detect_cookie_vendor(cookie)
                                if detected:
                                    vendor = detected
                                    signals.append(f"cookie:{cookie.split('=')[0].strip()}")
                                    break
                        # Collect X-Served-By values for variance detection
                        served_by = resp.headers.get("x-served-by") or resp.headers.get("via")
                        if served_by:
                            served_by_values.append(served_by)
        except Exception as exc:
            logger.warning("load_balancer_probe failed", host=host, error=str(exc))

        # Header variance: differing X-Served-By/Via values across responses indicates LB pool
        unique_served_by = set(served_by_values)
        if len(unique_served_by) > 1:
            if vendor is None:
                vendor = "generic_lb"
            signals.append(f"header_variance:x-served-by({len(unique_served_by)} unique)")

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "load_balancer_probe",
                "host": host,
                "detected": vendor is not None,
                "vendor": vendor or "none",
                "signals": signals,
                "served_by_variance": len(unique_served_by),
            },
        )
