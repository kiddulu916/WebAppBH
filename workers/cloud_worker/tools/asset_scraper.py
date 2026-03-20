"""AssetScraperTool -- Stage 1 dual-source cloud URL discovery.

Queries both the ``assets`` and ``cloud_assets`` tables for URLs
matching cloud provider patterns, deduplicates, and upserts into
``cloud_assets``.
"""

from __future__ import annotations

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool, detect_provider
from workers.cloud_worker.concurrency import WeightClass

logger = setup_logger("asset-scraper")

# Maps URL substring -> (provider, asset_type)
_URL_TYPE_MAP: list[tuple[str, str, str]] = [
    ("s3.amazonaws.com", "aws", "s3_bucket"),
    ("blob.core.windows.net", "azure", "blob_container"),
    ("storage.googleapis.com", "gcp", "gcs_bucket"),
    ("firebaseio.com", "gcp", "firebase_db"),
    ("appspot.com", "gcp", "appspot"),
]


class AssetScraperTool(CloudTestTool):
    """Scan assets + cloud_assets tables for cloud URLs."""

    name = "asset_scraper"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def classify_url(self, url: str) -> tuple[str, str] | None:
        """Return (provider, asset_type) for a cloud URL, or None."""
        lower = url.lower()
        for pattern, provider, asset_type in _URL_TYPE_MAP:
            if pattern in lower:
                return (provider, asset_type)
        return None

    @staticmethod
    def deduplicate(urls: list[str]) -> list[str]:
        """Deduplicate URLs preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for url in urls:
            normalized = url.rstrip("/").lower()
            if normalized not in seen:
                seen.add(normalized)
                result.append(url)
        return result

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping asset_scraper -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Source 1: assets table
        cloud_url_pairs = await self._get_cloud_urls_from_assets(target_id)
        asset_urls = [url for _, url in cloud_url_pairs]

        # Source 2: existing cloud_assets
        existing = await self._get_cloud_assets(target_id)
        existing_urls = [ca.url for ca in existing if ca.url]

        # Combine and deduplicate
        all_urls = self.deduplicate(asset_urls + existing_urls)
        stats["found"] = len(all_urls)

        # Upsert each into cloud_assets
        for url in all_urls:
            classification = self.classify_url(url)
            if classification is None:
                continue

            provider, asset_type = classification

            # Scope check
            scope_result = scope_manager.is_in_scope(url)
            if not scope_result.in_scope:
                continue

            stats["in_scope"] += 1
            await self._save_cloud_asset(
                target_id=target_id,
                provider=provider,
                asset_type=asset_type,
                url=url,
            )
            stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("asset_scraper complete", extra=stats)
        return stats
