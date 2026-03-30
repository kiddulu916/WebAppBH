# workers/info_gathering/tools/cookie_fingerprinter.py
"""CookieFingerprinter wrapper — analyze cookies for technology fingerprinting."""

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool


class CookieFingerprinter(InfoGatheringTool):
    """Analyze cookies to fingerprint technologies and frameworks."""

    # Known cookie patterns for technology detection
    COOKIE_PATTERNS = {
        "PHP": ["PHPSESSID"],
        "Java": ["JSESSIONID"],
        "ASP.NET": ["ASP.NET_SessionId", "__RequestVerificationToken"],
        "Django": ["csrftoken", "sessionid"],
        "Rails": ["_session_id"],
        "Laravel": ["laravel_session", "XSRF-TOKEN"],
        "WordPress": ["wordpress_logged_in", "wp-settings"],
        "Drupal": ["Drupal.visitor"],
        "Spring": ["JSESSIONID", "SPRING_SECURITY_REMEMBER_ME_COOKIE"],
    }

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        url = f"https://{target.base_domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    cookies = resp.cookies
                    if cookies:
                        detected_tech = self._analyze_cookies(cookies)
                        if detected_tech:
                            await self.save_observation(
                                target_id, "cookie_fingerprint",
                                {"host": target.base_domain, "technologies": detected_tech},
                                "cookie_fingerprinter"
                            )
        except Exception:
            pass

    def _analyze_cookies(self, cookies) -> list[str]:
        """Analyze cookies against known patterns."""
        detected = []
        cookie_names = set(cookies.keys())

        for tech, patterns in self.COOKIE_PATTERNS.items():
            if any(p in cookie_names for p in patterns):
                detected.append(tech)

        return detected