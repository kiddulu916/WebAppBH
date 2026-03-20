"""EndpointExtractorTool -- Stage 5: aggregate endpoints and feed back to recon.

Collects URLs/domains from Jadx source, MobSF reports, and Frida runtime data.
Deduplicates, scope-checks, upserts in-scope into assets, pushes to recon_queue.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from lib_webbh import push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("endpoint-extractor")

URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+")


class EndpointExtractorTool(MobileTestTool):
    """Extract endpoints from all prior stages, feed in-scope back to recon."""

    name = "endpoint_extractor"
    weight_class = WeightClass.STATIC

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
            log.info("Skipping endpoint_extractor -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        all_urls: list[str] = []
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        # Source 1: Jadx decompiled Java source
        for jadx_dir in analysis_dir.glob("*_jadx"):
            for java_file in jadx_dir.rglob("*.java"):
                try:
                    text = java_file.read_text(errors="replace")
                    all_urls.extend(self._extract_urls_from_text(text))
                except Exception:
                    pass

        # Source 2: MobSF reports
        for report_file in analysis_dir.glob("*_mobsf.json"):
            try:
                with open(report_file) as f:
                    report = json.load(f)
                all_urls.extend(self._extract_from_mobsf(report))
            except Exception:
                pass

        # Source 3: Frida runtime data (if captured to file)
        for frida_log in analysis_dir.glob("*_frida_urls.txt"):
            try:
                text = frida_log.read_text(errors="replace")
                all_urls.extend(self._extract_urls_from_text(text))
            except Exception:
                pass

        # Deduplicate
        unique_urls = self._deduplicate(all_urls)
        stats["found"] = len(unique_urls)

        # Scope-check and persist
        for url in unique_urls:
            asset_id = await self._save_asset(
                target_id, url, scope_manager, source_tool=self.name,
            )
            if asset_id is not None:
                stats["in_scope"] += 1
                stats["new"] += 1
                await self._push_to_recon(target_id, url)
            else:
                log.debug(f"Out-of-scope endpoint: {url}")

        await self.update_tool_state(target_id, container_name)
        log.info("endpoint_extractor complete", extra=stats)
        return stats

    @staticmethod
    def _extract_urls_from_text(text: str) -> list[str]:
        """Extract HTTP/HTTPS URLs from arbitrary text."""
        return URL_RE.findall(text)

    @staticmethod
    def _extract_from_mobsf(report: dict) -> list[str]:
        """Extract URLs and domains from MobSF JSON report."""
        urls: list[str] = []

        # urls section
        for entry in report.get("urls", []):
            if isinstance(entry, dict):
                url = entry.get("url", "")
                if url:
                    urls.append(url)
            elif isinstance(entry, str):
                urls.append(entry)

        # domains section
        domains = report.get("domains", {})
        if isinstance(domains, dict):
            for domain in domains:
                urls.append(domain)

        return urls

    @staticmethod
    def _deduplicate(urls: list[str]) -> list[str]:
        """Remove duplicate URLs while preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for url in urls:
            normalized = url.rstrip("/")
            if normalized not in seen:
                seen.add(normalized)
                result.append(url)
        return result

    @staticmethod
    async def _push_to_recon(target_id: int, url: str) -> None:
        """Push in-scope endpoint to recon_queue as high-priority task."""
        await push_task("recon_queue", {
            "target_id": target_id,
            "url": url,
            "priority": "high",
            "source": "mobile_endpoint_extractor",
        })
