# workers/info_gathering/tools/wappalyzer.py
"""Wappalyzer wrapper — technology detection (WSTG 4.1.8)."""
from __future__ import annotations

import json
from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool
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
    """Technology detection using Wappalyzer CLI (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            stdout = await self.run_subprocess(
                ["wappalyzer", f"https://{host}"], timeout=300,
                rate_limiter=kwargs.get("rate_limiter"),
            )
        except Exception as exc:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={}, error=str(exc))
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={}, error="invalid json")

        techs = data.get("technologies", [])
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for tech in techs:
            name = tech.get("name", "")
            slot = _TECH_SLOTS.get(name)
            if slot:
                signals[slot].append({"src": "wappalyzer", "value": name, "w": 0.6})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "wappalyzer", "host": host,
                        "technologies": [t.get("name", "") for t in techs]},
        )
        return ProbeResult(probe="wappalyzer", obs_id=obs_id, signals=signals)
