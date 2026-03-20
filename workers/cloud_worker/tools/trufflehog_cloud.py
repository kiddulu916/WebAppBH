"""TrufflehogCloudTool -- Stage 3 secret scanning on public buckets.

Runs TruffleHog with native cloud source support (S3, GCS) against
public buckets.  Verified secrets become critical vulns; unverified
become high.
"""

from __future__ import annotations

import json

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool
from workers.cloud_worker.concurrency import WeightClass
from workers.cloud_worker.tools.bucket_prober import BucketProberTool

logger = setup_logger("trufflehog-cloud")

TRUFFLEHOG_TIMEOUT = 600

_CREDENTIAL_DETECTORS = {"aws", "azure", "gcp", "privatekey", "googlecloud"}


class TrufflehogCloudTool(CloudTestTool):
    """Scan public cloud buckets for leaked secrets with TruffleHog."""

    name = "trufflehog_cloud"
    weight_class = WeightClass.HEAVY

    def build_command(self, bucket_name: str, provider: str) -> list[str]:
        if provider == "aws":
            return ["trufflehog", "s3", f"--bucket={bucket_name}", "--json", "--no-update"]
        if provider == "gcp":
            return ["trufflehog", "gcs", f"--bucket={bucket_name}", "--json", "--no-update"]
        return ["trufflehog", "filesystem", "/dev/null", "--json", "--no-update"]

    def parse_output(self, raw: str) -> list[dict]:
        if not raw.strip():
            return []
        findings: list[dict] = []
        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                finding: dict = {
                    "detector": data.get("DetectorName", "Unknown"),
                    "raw": data.get("Raw", ""),
                    "verified": data.get("Verified", False),
                    "source": "",
                }
                source_meta = data.get("SourceMetadata", {}).get("Data", {})
                for source_key in ("S3", "GCS", "Filesystem"):
                    if source_key in source_meta:
                        src = source_meta[source_key]
                        finding["source"] = src.get("file", src.get("bucket", ""))
                        break
                findings.append(finding)
            except json.JSONDecodeError:
                continue
        return findings

    @staticmethod
    def is_credential_type(detector: str) -> bool:
        return detector.lower() in _CREDENTIAL_DETECTORS

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
            log.info("Skipping trufflehog_cloud -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        public_assets = await self._get_public_cloud_assets(target_id)
        if not public_assets:
            log.info("No public cloud assets to scan")
            return stats

        prober = BucketProberTool()

        for ca in public_assets:
            if not ca.url:
                continue
            if ca.provider == "azure":
                log.info(f"Skipping Azure asset {ca.url} — no native trufflehog support")
                continue

            bucket_name = prober.extract_bucket_name(ca.url, ca.provider)
            if not bucket_name:
                continue

            cmd = self.build_command(bucket_name, ca.provider)

            try:
                raw = await self.run_subprocess(cmd, timeout=TRUFFLEHOG_TIMEOUT)
            except Exception as exc:
                log.error(f"trufflehog failed for {ca.url}: {exc}")
                continue

            findings = self.parse_output(raw)
            stats["found"] += len(findings)

            for finding in findings:
                severity = "critical" if finding["verified"] else "high"
                detector = finding["detector"]
                raw_secret = finding["raw"]
                masked = raw_secret[:6] + "..." if len(raw_secret) > 6 else "***"

                await self._save_vulnerability(
                    target_id=target_id,
                    asset_id=None,
                    severity=severity,
                    title=(
                        f"{'Verified' if finding['verified'] else 'Potential'} "
                        f"secret ({detector}) in {ca.provider.upper()} bucket"
                    ),
                    description=(
                        f"TruffleHog found a {detector} secret in bucket {bucket_name}. "
                        f"Source: {finding['source']}. Masked: {masked}. "
                        f"Verified: {finding['verified']}."
                    ),
                    poc=f"Bucket: {bucket_name}, Source: {finding['source']}",
                )
                stats["in_scope"] += 1
                stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("trufflehog_cloud complete", extra=stats)
        return stats
