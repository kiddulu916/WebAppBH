# workers/info_gathering/tools/error_page_probe.py
"""ErrorPageProbe — fingerprint default 404/error pages via a random path GET.

Picks a 16-hex-char random URL path that no real site serves, captures the
response body, hashes it, and substring-matches against a small table of
known default-error-page strings. Matches emit ``error_page_signature``
signals into the appropriate slot (origin_server for server defaults,
framework for app defaults).
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Any

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

# Body-substring → (signature_id, vendor) tuple. Order matters for first-match.
# Order matters: first match wins, so list the most-specific needle first.
# Tomcat pages contain both "Apache Tomcat" and "Apache" — the longer needle
# must come first to keep Tomcat from being misclassified as Apache.
_SIGNATURES: list[tuple[str, str, str]] = [
    ("<center>nginx",        "nginx-default-404",      "nginx"),
    ("Apache Tomcat",        "tomcat-default-404",     "Tomcat"),
    ("Apache",               "apache-default-404",     "Apache"),
    ("Microsoft-IIS",        "iis-default-404",        "IIS"),
    ("Cannot GET /",         "express-default-404",    "Express"),
    ("DEBUG = True",         "django-default-debug",   "Django"),
    ("ray id",               "cloudflare-default-404", "Cloudflare"),
]

_FRAMEWORK_VENDORS = frozenset({"Express", "Django"})
_EDGE_VENDORS = frozenset({"Cloudflare"})


class ErrorPageProbe(InfoGatheringTool):
    """Stage 2 default-error-page fingerprint probe."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return ProbeResult(
                probe="error_page", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        rate_limiter = kwargs.get("rate_limiter")
        random_path = secrets.token_hex(8)  # 16 hex chars
        url = f"https://{host}/{random_path}"
        try:
            await self.acquire_rate_limit(rate_limiter)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    status = resp.status
        except Exception as exc:
            return ProbeResult(
                probe="error_page", obs_id=None, signals={}, error=str(exc),
            )

        body_sha = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        signature_match: str | None = None
        signature_vendor: str | None = None
        body_lower = body.lower()
        for needle, sig_id, vendor in _SIGNATURES:
            if needle.lower() in body_lower:
                signature_match = sig_id
                signature_vendor = vendor
                break

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "error_page_404",
                "body_sha256": body_sha,
                "body_len": len(body),
                "signature_match": signature_match,
                "intensity": intensity,
            },
            status_code=status,
        )
        signals: dict[str, Any] = {"origin_server": [], "framework": [], "edge": []}
        if signature_vendor:
            slot = (
                "framework" if signature_vendor in _FRAMEWORK_VENDORS
                else "edge" if signature_vendor in _EDGE_VENDORS
                else "origin_server"
            )
            signals[slot].append({
                "src": "error_page_signature",
                "value": signature_vendor,
                "w": 0.7,
            })
        return ProbeResult(probe="error_page", obs_id=obs_id, signals=signals)
