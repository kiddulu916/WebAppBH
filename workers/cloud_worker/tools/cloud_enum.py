# workers/cloud_worker/tools/cloud_enum.py
"""CloudEnumTool -- Stage 1 multi-cloud OSINT discovery.

Wraps the cloud_enum tool to discover S3 buckets, Azure containers,
and GCP buckets associated with a target domain.
"""

from __future__ import annotations

import re

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool, detect_provider
from workers.cloud_worker.concurrency import WeightClass

logger = setup_logger("cloud-enum-tool")

CLOUD_ENUM_TIMEOUT = 300

# Regex to extract cloud URLs from cloud_enum output
_URL_RE = re.compile(
    r"([\w.-]+\.s3\.amazonaws\.com"
    r"|[\w.-]+\.blob\.core\.windows\.net/[\w.-]+"
    r"|storage\.googleapis\.com/[\w.-]+"
    r"|[\w.-]+\.appspot\.com"
    r"|[\w.-]+\.firebaseio\.com)"
)


class CloudEnumTool(CloudTestTool):
    """Discover cloud resources via cloud_enum OSINT tool."""

    name = "cloud_enum"
    weight_class = WeightClass.HEAVY

    def build_command(
        self,
        keyword: str,
        mutations: list[str] | None = None,
    ) -> list[str]:
        """Build the cloud_enum CLI command list."""
        cmd = ["cloud_enum", "-k", keyword]
        if mutations:
            for m in mutations:
                cmd.extend(["-m", m])
        return cmd

    def parse_output(self, raw: str) -> list[str]:
        """Extract cloud resource URLs from cloud_enum stdout."""
        if not raw.strip():
            return []
        matches = _URL_RE.findall(raw)
        seen: set[str] = set()
        results: list[str] = []
        for m in matches:
            if m.lower() not in seen:
                seen.add(m.lower())
                results.append(m)
        return results

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
            log.info("Skipping cloud_enum -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        keyword = profile.get("primary_domain", "")
        if not keyword:
            keyword = getattr(target, "name", "")
        if not keyword:
            log.warning("No keyword for cloud_enum — skipping")
            return stats

        mutations = profile.get("cloud_keywords", [])
        cmd = self.build_command(keyword, mutations)

        try:
            raw = await self.run_subprocess(cmd, timeout=CLOUD_ENUM_TIMEOUT)
        except Exception as exc:
            log.error(f"cloud_enum failed: {exc}")
            return stats

        urls = self.parse_output(raw)
        stats["found"] = len(urls)

        from workers.cloud_worker.tools.asset_scraper import AssetScraperTool
        scraper = AssetScraperTool()

        for url in urls:
            classification = scraper.classify_url(url)
            if classification is None:
                continue

            provider, asset_type = classification

            scope_result = scope_manager.is_in_scope(url)
            if not scope_result.in_scope:
                continue

            stats["in_scope"] += 1
            full_url = url if url.startswith("http") else f"https://{url}"
            await self._save_cloud_asset(
                target_id=target_id,
                provider=provider,
                asset_type=asset_type,
                url=full_url,
            )
            stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("cloud_enum complete", extra=stats)
        return stats
