# workers/cloud_worker/tools/cloud_feedbacker.py
"""CloudFeedbackerTool -- Stage 4 endpoint feed-back and credential alerting.

Extracts domains/IPs from discovered cloud assets, pushes in-scope
ones to recon_queue, and generates cloud_credential_leak alerts for
any credential-type findings from TruffleHog.
"""

from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import Vulnerability, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool
from workers.cloud_worker.concurrency import WeightClass

logger = setup_logger("cloud-feedbacker")

_CREDENTIAL_KEYWORDS = ["aws", "azure", "gcp", "privatekey", "googlecloud"]


class CloudFeedbackerTool(CloudTestTool):
    """Push cloud discoveries to recon_queue and generate credential alerts."""

    name = "cloud_feedbacker"
    weight_class = WeightClass.LIGHT

    @staticmethod
    def extract_domains(urls: list[str]) -> list[str]:
        domains: list[str] = []
        seen: set[str] = set()
        for url in urls:
            full = url if url.startswith("http") else f"https://{url}"
            parsed = urlparse(full)
            host = parsed.hostname
            if host and host not in seen:
                seen.add(host)
                domains.append(host)
        return domains

    @staticmethod
    def is_credential_vuln(title: str) -> bool:
        lower = title.lower()
        return any(kw in lower for kw in _CREDENTIAL_KEYWORDS) and "secret" in lower

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
            log.info("Skipping cloud_feedbacker -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        cloud_assets = await self._get_cloud_assets(target_id)
        urls = [ca.url for ca in cloud_assets if ca.url]
        domains = self.extract_domains(urls)
        stats["found"] = len(domains)

        for domain in domains:
            asset_id = await self._save_asset(
                target_id=target_id,
                url=f"https://{domain}",
                scope_manager=scope_manager,
                source_tool="cloud_feedbacker",
            )
            if asset_id is not None:
                stats["in_scope"] += 1
                stats["new"] += 1
                await push_task("recon_queue", {
                    "target_id": target_id,
                    "asset_id": asset_id,
                    "source": "cloud_feedbacker",
                    "priority": "high",
                })

        async with get_session() as session:
            stmt = select(Vulnerability).where(
                Vulnerability.target_id == target_id,
                Vulnerability.source_tool == "trufflehog_cloud",
            )
            result = await session.execute(stmt)
            vulns = list(result.scalars().all())

        for vuln in vulns:
            if self.is_credential_vuln(vuln.title):
                log.warning(
                    f"Cloud credential leak detected: {vuln.title}",
                    extra={"vuln_id": vuln.id},
                )
                await push_task(f"events:{target_id}", {
                    "event": "CLOUD_CREDENTIAL_LEAK",
                    "vulnerability_id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "message": f"Cloud credential leaked: {vuln.title}",
                })

        await self.update_tool_state(target_id, container_name)
        log.info("cloud_feedbacker complete", extra=stats)
        return stats
