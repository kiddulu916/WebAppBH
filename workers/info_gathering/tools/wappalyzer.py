# workers/info_gathering/tools/wappalyzer.py
"""Wappalyzer wrapper — technology detection (WSTG 4.1.8)."""
from __future__ import annotations

from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool, logger
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_TECH_SLOTS: dict[str, str] = {
    "Laravel": "framework", "Django": "framework", "Ruby on Rails": "framework",
    "Express": "framework", "ASP.NET MVC": "framework", "Spring Boot": "framework",
    "Spring Framework": "framework", "Flask": "framework", "Symfony": "framework",
    "CodeIgniter": "framework", "Nuxt.js": "framework", "Next.js": "framework",
    "WordPress": "cms", "Joomla": "cms", "Drupal": "cms", "Ghost": "cms",
    "Magento": "cms", "PrestaShop": "cms", "TYPO3": "cms", "Shopify": "cms",
    "PHP": "language", "Python": "language", "Ruby": "language", "Java": "language",
    "Node.js": "language", "ASP.NET": "language",
}


class Wappalyzer(InfoGatheringTool):
    """Technology detection using python-Wappalyzer library (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        import asyncio
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            from Wappalyzer import Wappalyzer as WapLib, WebPage
            webpage = await asyncio.get_event_loop().run_in_executor(
                None, WebPage.new_from_url, f"https://{host}"
            )
            wappalyzer = WapLib.latest()
            techs = await asyncio.get_event_loop().run_in_executor(
                None, wappalyzer.analyze, webpage
            )
        except Exception as exc:
            logger.error("wappalyzer failed", host=host, error=str(exc))
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={}, error=str(exc))

        tech_names = list(techs) if isinstance(techs, (set, list)) else list(techs.keys())
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for name in tech_names:
            slot = _TECH_SLOTS.get(name)
            if slot:
                signals[slot].append({"src": "wappalyzer", "value": name, "w": 0.6})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "wappalyzer", "host": host, "technologies": tech_names},
        )
        return ProbeResult(probe="wappalyzer", obs_id=obs_id, signals=signals)
