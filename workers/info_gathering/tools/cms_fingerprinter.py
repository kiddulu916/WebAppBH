"""CMSFingerprinter — BlindElephant-style CMS detection (WSTG 4.1.8 / merged INFO-09)."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-cms-fingerprinter")

_DB_PATH = Path(__file__).parent.parent / "data" / "cms_fingerprints.json"
_CONCURRENCY = 5
_ACCESSIBLE = frozenset({200, 301, 302})


async def _fetch_path(
    sess: "aiohttp.ClientSession",
    host: str,
    path: str,
    sem: asyncio.Semaphore,
    confirmed_paths: list[str],
    fetched_bodies: dict[str, bytes],
) -> None:
    """Fetch one probe path; append to confirmed_paths/fetched_bodies on success."""
    try:
        async with sem:
            async with sess.get(
                f"https://{host}{path}",
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
            ) as resp:
                if resp.status in _ACCESSIBLE:
                    confirmed_paths.append(path)
                    fetched_bodies[path] = await resp.read()
    except Exception as exc:
        logger.debug("cms_fingerprinter probe failed", extra={"host": host, "path": path, "error": str(exc)})

# Canonical display names for known CMS keys (lowercase key → display name).
# Used when the DB entry lacks a "display_name" field.
_CMS_DISPLAY_NAMES: dict[str, str] = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "magento": "Magento",
    "typo3": "TYPO3",
    "django": "Django",
    "laravel": "Laravel",
    "symfony": "Symfony",
}


class CMSFingerprinter(InfoGatheringTool):
    """BlindElephant-style CMS detection: path probing + MD5 hash version matching (WSTG 4.1.8)."""

    def _load_db(self) -> dict:
        with open(_DB_PATH) as f:
            return json.load(f)

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="cms_fingerprinter", obs_id=None, signals={},
                               error="missing host or asset_id")

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        db = self._load_db()
        signals: dict[str, Any] = {"cms": []}
        sem = asyncio.Semaphore(_CONCURRENCY)

        for cms_name, cms_data in db.items():
            probe_paths: list[str] = cms_data.get("probe_paths", [])
            versions: dict[str, dict[str, str]] = cms_data.get("versions", {})

            # Phase 1: confirm presence via probe paths
            confirmed_paths: list[str] = []
            fetched_bodies: dict[str, bytes] = {}

            async with aiohttp.ClientSession() as sess:
                await asyncio.gather(*[
                    _fetch_path(sess, host, p, sem, confirmed_paths, fetched_bodies)
                    for p in probe_paths
                ])

            if not confirmed_paths:
                continue

            # Phase 2: version matching via MD5 hash comparison
            fetched_hashes = {
                path: hashlib.md5(body).hexdigest()
                for path, body in fetched_bodies.items()
            }

            best_version: str | None = None
            best_match_count = 0
            best_confidence = 0.0

            for version, version_hashes in versions.items():
                if not version_hashes:
                    continue
                matched = sum(
                    1 for path, expected_hash in version_hashes.items()
                    if fetched_hashes.get(path) == expected_hash
                )
                if matched == 0:
                    continue
                confidence = matched / len(version_hashes)
                # Prefer version with most matches; break ties by confidence
                if matched > best_match_count or (
                    matched == best_match_count and confidence > best_confidence
                ):
                    best_match_count = matched
                    best_confidence = confidence
                    best_version = version

            version_label = best_version if best_version else "unknown"
            display_name = cms_data.get("display_name") or _CMS_DISPLAY_NAMES.get(
                cms_name.lower(), cms_name.capitalize()
            )
            sig: dict[str, Any] = {
                "src": "cms_fingerprinter",
                "value": display_name,
                "w": 0.9 if best_version else 0.5,
                "version": version_label,
                "confidence": best_confidence,
                "confirmed_paths": confirmed_paths,
            }
            signals["cms"].append(sig)

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "cms_fingerprinter",
                "host": host,
                "detections": signals["cms"],
            },
        )
        return ProbeResult(probe="cms_fingerprinter", obs_id=obs_id, signals=signals)
