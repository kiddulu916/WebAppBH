# workers/info_gathering/tools/meta_generator_probe.py
"""MetaGeneratorProbe — HTML meta generator tag fingerprinting (WSTG 4.1.8)."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-meta-generator-probe")

# (regex, slot, vendor, version_capture_group_or_None)
_GENERATOR_PATTERNS: list[tuple[str, str, str, int | None]] = [
    (r"(?i)wordpress\s*([\d.]+)?", "cms",       "WordPress", 1),
    (r"(?i)joomla!?\s*([\d.]+)?",  "cms",       "Joomla",    1),
    (r"(?i)drupal\s*([\d.]+)?",    "cms",       "Drupal",    1),
    (r"(?i)ghost\s*([\d.]+)?",     "cms",       "Ghost",     1),
]


class _PageParser(HTMLParser):
    """Extracts framework-identifying signals from an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.generator: str | None = None
        self.has_wp_api_link: bool = False
        self.has_rails_csrf_param: bool = False
        self.has_drupal_attr: bool = False
        self.has_django_csrf: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = dict(attrs)
        if tag == "meta":
            name = (d.get("name") or "").lower()
            if name == "generator":
                self.generator = d.get("content") or ""
            elif name == "csrf-param" and (d.get("content") or "") == "authenticity_token":
                self.has_rails_csrf_param = True
        elif tag == "link":
            href = d.get("href") or ""
            rel = d.get("rel") or ""
            if "api.w.org" in href or "api.w.org" in rel:
                self.has_wp_api_link = True
        elif tag == "input" and (d.get("name") or "") == "csrfmiddlewaretoken":
            self.has_django_csrf = True
        for attr_name, _ in attrs:
            if attr_name.startswith("data-drupal"):
                self.has_drupal_attr = True


class MetaGeneratorProbe(InfoGatheringTool):
    """HTML meta-tag and secondary-signal framework fingerprinting (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="meta_generator", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            await self.acquire_rate_limit(kwargs.get("rate_limiter"))
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    html = await resp.text(errors="replace")
        except Exception as exc:
            logger.warning("meta_generator_probe failed", extra={"host": host, "error": str(exc)})
            return ProbeResult(probe="meta_generator", obs_id=None, signals={}, error=str(exc))

        parser = _PageParser()
        parser.feed(html)
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        tech_stack: dict[str, Any] = {"_probe": "meta_generator", "host": host}

        if parser.generator:
            tech_stack["generator"] = parser.generator
            for pattern, slot, vendor, vg in _GENERATOR_PATTERNS:
                m = re.search(pattern, parser.generator)
                if m:
                    sig: dict[str, Any] = {"src": "meta_generator", "value": vendor, "w": 0.8}
                    if vg and m.lastindex and m.lastindex >= vg:
                        ver = m.group(vg)
                        if ver:
                            sig["version"] = ver
                    signals[slot].append(sig)
                    break

        if parser.has_wp_api_link and not any(
            s["value"] == "WordPress" for s in signals["cms"]
        ):
            signals["cms"].append({"src": "meta_generator", "value": "WordPress", "w": 0.5})

        if parser.has_drupal_attr and not any(
            s["value"] == "Drupal" for s in signals["cms"]
        ):
            signals["cms"].append({"src": "meta_generator", "value": "Drupal", "w": 0.4})

        if parser.has_rails_csrf_param:
            signals["framework"].append(
                {"src": "meta_generator", "value": "Rails", "w": 0.5})

        if parser.has_django_csrf:
            signals["framework"].append(
                {"src": "meta_generator", "value": "Django", "w": 0.5})

        obs_id = await self.save_observation(asset_id=asset_id, tech_stack=tech_stack)
        return ProbeResult(probe="meta_generator", obs_id=obs_id, signals=signals)
