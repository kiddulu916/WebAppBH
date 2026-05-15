# workers/info_gathering/tools/meta_tag_analyzer.py
"""MetaTagAnalyzer — WSTG-INFO-03: extract <meta> tags from page root for information leakage."""

import asyncio
from html.parser import HTMLParser

import aiohttp

MAX_BODY_BYTES = 512 * 1024  # 512 KB cap for meta tag parsing

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class _HeadMetaCollector(HTMLParser):
    """Collects <meta> tag attribute dicts from the HTML <head> only."""

    def __init__(self):
        super().__init__()
        self.metas: list[dict[str, str]] = []
        self._in_head = False
        self._done = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._done:
            return
        if tag == "head":
            self._in_head = True
        elif tag == "body":
            self._done = True
        elif tag == "meta" and self._in_head:
            self.metas.append({k: (v or "") for k, v in attrs})

    def handle_endtag(self, tag: str) -> None:
        if tag == "head":
            self._done = True


class MetaTagAnalyzer(InfoGatheringTool):
    """Extract <meta> tags from the page root and tag findings for downstream workers."""

    async def execute(self, target_id: int, **kwargs) -> None:
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or asset_id is None:
            return

        host = kwargs.get("host") or target.base_domain
        rate_limiter = kwargs.get("rate_limiter")

        log = logger.bind(target_id=target_id, host=host)
        log.info("meta_tag_analyzer starting")

        await self.acquire_rate_limit(rate_limiter)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}/",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return
                    raw = await resp.content.read(MAX_BODY_BYTES)
                    html = raw.decode("utf-8", errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.warning("meta_tag_analyzer fetch failed", host=host, error=str(exc))
            return

        findings = self._parse_meta_tags(html)

        if findings.get("robots_directive"):
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "meta_tag",
                    "intel_type": "meta_robots",
                    "tags": ["intel:crawler-hint"],
                    "data": {"directive": findings["robots_directive"]},
                },
            )

        social = {
            k: v for k, v in findings.items()
            if k.startswith(("og_", "twitter_")) and v
        }
        if social:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "meta_tag",
                    "intel_type": "meta_social",
                    "tags": ["intel:social-account", "intel:site-structure"],
                    "data": social,
                },
            )

        generator = {k: v for k, v in findings.items() if k in ("generator", "application_name") and v}
        if generator:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "meta_tag",
                    "intel_type": "meta_generator",
                    "tags": ["intel:tech-stack", "candidate:version-disclosure"],
                    "data": generator,
                },
            )

        log.info("meta_tag_analyzer complete")

    def _parse_meta_tags(self, html: str) -> dict[str, str]:
        collector = _HeadMetaCollector()
        collector.feed(html)

        result: dict[str, str] = {}
        for meta in collector.metas:
            name = (meta.get("name") or meta.get("property") or "").lower()
            content = meta.get("content", "")
            if not content:
                continue

            if name == "robots":
                result["robots_directive"] = content
            elif name == "og:url":
                result["og_url"] = content
            elif name == "og:site_name":
                result["og_site_name"] = content
            elif name == "og:title":
                result["og_title"] = content
            elif name == "twitter:creator":
                result["twitter_creator"] = content
            elif name == "twitter:site":
                result["twitter_site"] = content
            elif name == "twitter:card":
                result["twitter_card"] = content
            elif name == "generator":
                result["generator"] = content
            elif name == "application-name":
                result["application_name"] = content

        return result
