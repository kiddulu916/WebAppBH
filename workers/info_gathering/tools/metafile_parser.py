# workers/info_gathering/tools/metafile_parser.py
"""MetafileParser — WSTG-INFO-03: review webserver metafiles for information leakage."""

import asyncio
import re

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger

MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB cap — prevents memory exhaustion from attacker-controlled responses

_SENSITIVE_PREFIXES = (
    "/admin", "/api", "/internal", "/config", "/backup",
    "/staging", "/dev", "/test", "/dashboard", "/manage",
    "/private", "/.git", "/.env",
)

_WELL_KNOWN_PATHS = [
    "openid-configuration",
    "oauth-authorization-server",
    "webfinger",
    "change-password",
    "mta-sts.txt",
    "dmarc",
    "pki-validation",
    "apple-app-site-association",
    "assetlinks.json",
    "nodeinfo",
    "host-meta",
    "caldav",
    "carddav",
]

_WELL_KNOWN_AUTH = frozenset({
    "openid-configuration",
    "oauth-authorization-server",
    "change-password",
    "webfinger",
})

_SITEMAP_URL_CAP = 500
_SITEMAP_BATCH_SIZE = 50
_SITEMAP_CHILD_CAP = 3


class MetafileParser(InfoGatheringTool):
    """Parse robots.txt, sitemap.xml, security.txt, humans.txt, and .well-known/ endpoints."""

    async def execute(self, target_id: int, **kwargs) -> None:
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or asset_id is None:
            return

        host = kwargs.get("host") or target.base_domain
        base_url = f"https://{host}"
        rate_limiter = kwargs.get("rate_limiter")

        log = logger.bind(target_id=target_id, host=host)
        log.info("metafile_parser starting")

        async with aiohttp.ClientSession() as session:
            # Phase 1: robots.txt first — returns declared Sitemap: refs
            robots_sitemaps = await self._fetch_robots(
                session, base_url, target_id, asset_id, rate_limiter
            )

            # Phase 2: remaining fetches concurrently
            await asyncio.gather(
                self._fetch_sitemap(
                    session, base_url, target_id, asset_id, rate_limiter,
                    extra_urls=robots_sitemaps,
                ),
                self._fetch_security_txt(session, base_url, target_id, asset_id, rate_limiter),
                self._fetch_humans_txt(session, base_url, target_id, asset_id, rate_limiter),
                self._probe_well_known(session, base_url, target_id, asset_id, rate_limiter),
                return_exceptions=True,
            )

        log.info("metafile_parser complete")

    async def _get(
        self, session: aiohttp.ClientSession, url: str, rate_limiter=None
    ) -> tuple[int, str] | None:
        """GET url; return (status, body_text) or None on connection error."""
        await self.acquire_rate_limit(rate_limiter)
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=False,
            ) as resp:
                if resp.status == 200:
                    raw = await resp.content.read(MAX_BODY_BYTES)
                    body = raw.decode("utf-8", errors="replace")
                else:
                    body = ""
                return resp.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError) as exc:
            logger.warning("metafile_parser._get failed", url=url, error=str(exc))
            return None

    def _is_same_origin(self, url: str, base_url: str) -> bool:
        """Return True only if url shares the same scheme+host as base_url."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            base = urlparse(base_url)
            return parsed.scheme in ("http", "https") and parsed.netloc == base.netloc
        except Exception:
            return False

    # ------------------------------------------------------------------ robots
    async def _fetch_robots(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> list[str]:
        """Fetch robots.txt, write per-path observations, return declared Sitemap: URLs."""
        result = await self._get(session, f"{base_url}/robots.txt", rate_limiter)
        if not result or result[0] != 200:
            return []

        _, content = result
        parsed = self._parse_robots(content)

        for path in parsed["disallow"]:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "robots_txt",
                    "intel_type": "hidden_path",
                    "tags": self._tags_for_path(path),
                    "data": {"path": path, "context": "Disallow"},
                },
            )

        if parsed["user_agents"] or parsed["allow"]:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "robots_txt",
                    "intel_type": "crawler_policy",
                    "tags": ["intel:crawler-hint"],
                    "data": {
                        "user_agents": parsed["user_agents"],
                        "allow": parsed["allow"],
                    },
                },
            )

        return [s for s in parsed["sitemaps"] if self._is_same_origin(s, base_url)]

    # ------------------------------------------------------------------ sitemap
    async def _fetch_sitemap(
        self, session, base_url, target_id, asset_id, rate_limiter,
        extra_urls: list[str] | None = None,
    ) -> None:
        urls_to_fetch = [f"{base_url}/sitemap.xml"]
        if extra_urls:
            urls_to_fetch += [u for u in extra_urls if u not in urls_to_fetch]

        all_urls: list[str] = []
        child_count = 0

        for sitemap_url in urls_to_fetch:
            result = await self._get(session, sitemap_url, rate_limiter)
            if not result or result[0] != 200:
                continue
            parsed = self._parse_sitemap(result[1])
            all_urls.extend(parsed["urls"])

            for child_url in parsed["nested_sitemaps"]:
                if child_count >= _SITEMAP_CHILD_CAP:
                    break
                if not self._is_same_origin(child_url, base_url):
                    continue
                child = await self._get(session, child_url, rate_limiter)
                if child and child[0] == 200:
                    all_urls.extend(self._parse_sitemap(child[1])["urls"])
                    child_count += 1

            if len(all_urls) >= _SITEMAP_URL_CAP:
                break

        all_urls = list(dict.fromkeys(all_urls))[:_SITEMAP_URL_CAP]
        if not all_urls:
            return

        for batch_num, i in enumerate(range(0, len(all_urls), _SITEMAP_BATCH_SIZE)):
            batch = all_urls[i : i + _SITEMAP_BATCH_SIZE]
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "sitemap_xml",
                    "intel_type": "sitemap_url",
                    "tags": ["candidate:entry-point", "intel:site-structure"],
                    "data": {"urls": batch, "batch": batch_num},
                },
            )

    # ------------------------------------------------------------------ security.txt
    async def _fetch_security_txt(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> None:
        for path in ("/.well-known/security.txt", "/security.txt"):
            result = await self._get(session, f"{base_url}{path}", rate_limiter)
            if not result or result[0] != 200:
                continue
            parsed = self._parse_security_txt(result[1])
            if not any(v for v in parsed.values() if v):
                continue
            tags = ["intel:security-contact"]
            if parsed.get("hiring"):
                tags.append("intel:employee-pii")
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "security_txt",
                    "intel_type": "security_contact",
                    "tags": tags,
                    "data": parsed,
                },
            )
            return  # stop at first 200 (prefers /.well-known/)

    # ------------------------------------------------------------------ humans.txt
    async def _fetch_humans_txt(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> None:
        result = await self._get(session, f"{base_url}/humans.txt", rate_limiter)
        if not result or result[0] != 200:
            return
        parsed = self._parse_humans_txt(result[1])
        if not parsed["team"] and not parsed["tech_credits"]:
            return
        tags = []
        if parsed["team"]:
            tags.append("intel:employee-pii")
        if parsed["tech_credits"]:
            tags.append("intel:tech-stack")
        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "source": "humans_txt",
                "intel_type": "employee_info",
                "tags": tags,
                "data": parsed,
            },
        )

    # ------------------------------------------------------------------ .well-known
    async def _probe_well_known(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> None:
        async def _probe_one(path: str) -> None:
            result = await self._get(session, f"{base_url}/.well-known/{path}", rate_limiter)
            if not result or result[0] not in (200, 301, 302, 307, 308):
                return
            tags = ["intel:hidden-path"]
            if path in _WELL_KNOWN_AUTH:
                tags.append("candidate:authn-bypass")
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "well_known_probe",
                    "intel_type": "well_known_endpoint",
                    "tags": tags,
                    "data": {"path": f"/.well-known/{path}", "status_code": result[0]},
                },
            )

        await asyncio.gather(
            *[_probe_one(p) for p in _WELL_KNOWN_PATHS],
            return_exceptions=True,
        )

    # ------------------------------------------------------------------ pure parsers
    def _tags_for_path(self, path: str) -> list[str]:
        tags = ["intel:hidden-path"]
        if any(path.lower().startswith(p) for p in _SENSITIVE_PREFIXES):
            tags += ["candidate:forced-browsing", "candidate:authn-bypass"]
        return tags

    def _parse_robots(self, content: str) -> dict:
        def _lines(field: str) -> list[str]:
            return [
                m.strip()
                for m in re.findall(rf"^{re.escape(field)}:[^\S\n]*(.+)", content, re.IGNORECASE | re.MULTILINE)
                if m.strip()
            ]
        return {
            "disallow": _lines("Disallow"),
            "allow": _lines("Allow"),
            "user_agents": [u for u in _lines("User-agent") if u != "*"],
            "sitemaps": _lines("Sitemap"),
        }

    def _parse_sitemap(self, content: str) -> dict:
        nested = re.findall(
            r"<sitemap[^>]*>.*?<loc>(.*?)</loc>.*?</sitemap>",
            content, re.IGNORECASE | re.DOTALL,
        )
        clean = re.sub(r"<sitemap[^>]*>.*?</sitemap>", "", content, flags=re.IGNORECASE | re.DOTALL)
        urls = re.findall(r"<loc>(.*?)</loc>", clean, re.IGNORECASE | re.DOTALL)
        return {
            "urls": [u.strip() for u in urls if u.strip()],
            "nested_sitemaps": [u.strip() for u in nested if u.strip()][:_SITEMAP_CHILD_CAP],
        }

    def _parse_security_txt(self, content: str) -> dict:
        def _field(name: str) -> list[str]:
            return [
                m.strip()
                for m in re.findall(rf"^{re.escape(name)}:[^\S\n]*(.+)", content, re.IGNORECASE | re.MULTILINE)
                if m.strip()
            ]
        return {
            "contacts": _field("Contact"),
            "policies": _field("Policy"),
            "encryption": _field("Encryption"),
            "acknowledgments": _field("Acknowledgments"),
            "hiring": _field("Hiring"),
            "expires": next(iter(_field("Expires")), None),
            "canonical": _field("Canonical"),
            "preferred_languages": _field("Preferred-Languages"),
        }

    def _parse_humans_txt(self, content: str) -> dict:
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in content.splitlines():
            stripped = line.strip()
            m = re.match(r"/\*\s*(.+?)\s*\*/", stripped)
            if m:
                current = m.group(1).upper()
                sections[current] = []
            elif current and stripped:
                sections[current].append(stripped)

        team = []
        for line in sections.get("TEAM", []):
            if ":" in line:
                key, _, val = line.partition(":")
                team.append({"field": key.strip(), "value": val.strip()})

        tech_credits = sections.get("SITE", []) + sections.get("TECHNOLOGY", [])
        return {
            "team": team,
            "tech_credits": tech_credits,
            "raw_sections": {
                k: v for k, v in sections.items() if k not in ("TEAM", "SITE", "TECHNOLOGY")
            },
        }
