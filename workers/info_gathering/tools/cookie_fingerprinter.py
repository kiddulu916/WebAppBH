# workers/info_gathering/tools/cookie_fingerprinter.py
"""CookieFingerprinter — cookie-based technology fingerprinting (WSTG 4.1.8)."""
from __future__ import annotations

from typing import Any

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_COOKIE_TECH_SLOTS: dict[str, str] = {
    "PHP": "language", "Java": "language", "ASP.NET": "language",
    "Django": "framework", "Rails": "framework", "Laravel": "framework",
    "Spring": "framework", "WordPress": "cms", "Drupal": "cms",
}


class CookieFingerprinter(InfoGatheringTool):
    """Cookie-name-based framework fingerprinting (WSTG 4.1.8)."""

    COOKIE_PATTERNS = {
        "PHP": ["PHPSESSID"],
        "Java": ["JSESSIONID"],
        "ASP.NET": ["ASP.NET_SessionId", "__RequestVerificationToken"],
        "Django": ["csrftoken", "sessionid"],
        "Rails": ["_session_id"],
        "Laravel": ["laravel_session", "XSRF-TOKEN"],
        "WordPress": ["wordpress_logged_in", "wp-settings"],
        "Drupal": ["Drupal.visitor"],
        "Spring": ["SPRING_SECURITY_REMEMBER_ME_COOKIE"],
    }

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="cookie_framework", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            await self.acquire_rate_limit(kwargs.get("rate_limiter"))
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    cookies = resp.cookies
        except Exception as exc:
            return ProbeResult(probe="cookie_framework", obs_id=None, signals={}, error=str(exc))

        detected = self._analyze_cookies(cookies)
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for tech_name in detected:
            slot = _COOKIE_TECH_SLOTS.get(tech_name, "framework")
            signals[slot].append({"src": "cookie_framework", "value": tech_name, "w": 0.5})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "cookie_framework", "host": host, "technologies": detected},
        )
        return ProbeResult(probe="cookie_framework", obs_id=obs_id, signals=signals)

    def _analyze_cookies(self, cookies) -> list[str]:
        detected, cookie_names = [], set(cookies.keys())
        for tech, patterns in self.COOKIE_PATTERNS.items():
            if any(p in cookie_names for p in patterns):
                detected.append(tech)
        return detected
