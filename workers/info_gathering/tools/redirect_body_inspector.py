# workers/info_gathering/tools/redirect_body_inspector.py
"""RedirectBodyInspector — detect sensitive content in 3xx redirect response bodies (WSTG-INFO-05)."""
import re

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r'\b(?:password|passwd|secret|api_key|apikey|token|auth)\s*[:=]\s*\S+', re.I),
        "credential_keyword",
    ),
    (
        re.compile(
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'
            r'|192\.168\.\d+\.\d+'
        ),
        "internal_ip",
    ),
    (
        re.compile(
            r'Traceback \(most recent call last\)'
            r'|at\s+[\w.$]+\([\w.:]+:\d+\)'
            r'|Exception in thread'
        ),
        "stack_trace",
    ),
]


class RedirectBodyInspector(InfoGatheringTool):
    """Fetch URLs without auto-redirect; scan 3xx response bodies for sensitive content."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        candidates = await self._get_url_assets(target_id)
        if not candidates:
            candidates = await self._urls_from_root(target.base_domain, target_id)

        for url, asset_id in candidates[:50]:
            await self._inspect(url, asset_id, target_id)

    async def _get_url_assets(self, target_id: int) -> list[tuple[str, int]]:
        """Return (url, asset_id) for URL assets not yet inspected."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value, Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                )
            )
            result = await session.execute(stmt)
            all_assets = result.all()
            if not all_assets:
                return []

            asset_ids = [row[1] for row in all_assets]
            processed_stmt = (
                select(Observation.asset_id)
                .where(
                    Observation.asset_id.in_(asset_ids),
                    Observation.tech_stack["_source"].astext == "redirect_body_inspector",
                )
            )
            processed_result = await session.execute(processed_stmt)
            processed_ids = {row[0] for row in processed_result.all()}

            return [(url, aid) for url, aid in all_assets if aid not in processed_ids]

    async def _urls_from_root(self, base_domain: str, target_id: int) -> list[tuple[str, int]]:
        """Parse root page links; create Asset records for fallback URLs."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://{base_domain}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
        except Exception as exc:
            logger.debug("redirect_body_inspector fallback fetch failed", error=str(exc))
            return []

        hrefs = re.findall(r'href=["\']([^"\'#?][^"\']*)["\']', html)
        results = []
        for href in hrefs[:50]:
            if href.startswith("//"):
                full_url = "https:" + href
            elif href.startswith("http"):
                full_url = href
            else:
                full_url = f"https://{base_domain}{href if href.startswith('/') else '/' + href}"
            aid = await self.save_asset(target_id, "url", full_url, "redirect_body_inspector")
            if aid is None:
                async with get_session() as session:
                    stmt = select(Asset.id).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == full_url,
                    )
                    r = await session.execute(stmt)
                    aid = r.scalar_one_or_none()
            if aid:
                results.append((full_url, aid))
        return results

    async def _inspect(self, url: str, asset_id: int, target_id: int) -> None:
        """Fetch url without redirect; save observation and vulnerability if body leaks data."""
        status = None
        body = None
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    if status not in range(300, 400):
                        return
                    body = await resp.text(errors="replace")
        except Exception:
            return

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_source": "redirect_body_inspector"},
            status_code=status,
        )

        matches = self._scan_body(body)
        if not matches:
            return

        match_types = sorted({t for _, t in matches})
        short_url = url if len(url) <= 456 else url[:453] + "..."
        await self.save_vulnerability(
            target_id=target_id,
            asset_id=asset_id,
            severity="low",
            title=f"Sensitive content in redirect response body: {short_url}",
            description=(
                f"The {status} redirect response for {url} contains sensitive patterns: "
                f"{', '.join(match_types)}. Browsers discard redirect bodies silently, "
                "so developers often overlook this leakage vector."
            ),
            source_tool="redirect_body_inspector",
            section_id="4.1.5",
            vuln_type="redirect_body_leakage",
            evidence={
                "url": url,
                "status_code": status,
                "matches": [{"type": t, "value": v[:200]} for v, t in matches],
            },
        )

    def _scan_body(self, body: str) -> list[tuple[str, str]]:
        """Return list of (matched_string, pattern_label) for all matches in body."""
        results = []
        for pattern, label in _PATTERNS:
            for m in pattern.finditer(body):
                results.append((m.group(), label))
        return results
