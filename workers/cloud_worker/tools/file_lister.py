# workers/cloud_worker/tools/file_lister.py
"""FileListerTool -- Stage 3 sensitive filename detection.

Lists objects in public cloud buckets and flags files matching
sensitive patterns (secrets, backups, configs, credentials).
"""

from __future__ import annotations

import re

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool
from workers.cloud_worker.concurrency import WeightClass
from workers.cloud_worker.tools.bucket_prober import BucketProberTool

logger = setup_logger("file-lister")

MAX_OBJECTS = 100

_CRITICAL_PATTERNS = [r"\.pem$", r"\.key$", r"\.ssh", r"id_rsa", r"id_ed25519"]
_HIGH_PATTERNS = [r"\.env$", r"\.env\.", r"credentials", r"\.sql$", r"\.pgpass", r"\.htpasswd", r"password"]
_MEDIUM_PATTERNS = [r"\.bak$", r"backup", r"dump", r"\.csv$", r"\.xlsx$", r"config", r"\.git"]

_ALL_PATTERNS = _CRITICAL_PATTERNS + _HIGH_PATTERNS + _MEDIUM_PATTERNS
_ALL_RE = [re.compile(p, re.IGNORECASE) for p in _ALL_PATTERNS]
_CRITICAL_RE = [re.compile(p, re.IGNORECASE) for p in _CRITICAL_PATTERNS]
_HIGH_RE = [re.compile(p, re.IGNORECASE) for p in _HIGH_PATTERNS]


class FileListerTool(CloudTestTool):
    """List objects in readable buckets and flag sensitive filenames."""

    name = "file_lister"
    weight_class = WeightClass.LIGHT

    def is_sensitive(self, filename: str) -> bool:
        """Return True if filename matches any sensitive pattern."""
        return any(r.search(filename) for r in _ALL_RE)

    def severity_for_file(self, filename: str) -> str:
        """Return severity based on filename pattern."""
        if any(r.search(filename) for r in _CRITICAL_RE):
            return "critical"
        if any(r.search(filename) for r in _HIGH_RE):
            return "high"
        return "medium"

    async def _list_s3(self, bucket_name: str) -> list[str]:
        import botocore.session
        from botocore import UNSIGNED
        from botocore.config import Config

        session = botocore.session.get_session()
        client = session.create_client("s3", config=Config(signature_version=UNSIGNED))
        try:
            resp = client.list_objects_v2(Bucket=bucket_name, MaxKeys=MAX_OBJECTS)
            return [obj["Key"] for obj in resp.get("Contents", [])]
        finally:
            client.close()

    async def _list_azure(self, url: str, container_name: str) -> list[str]:
        from urllib.parse import urlparse
        from azure.storage.blob import ContainerClient

        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        account_url = f"{parsed.scheme}://{parsed.hostname}"
        client = ContainerClient(account_url=account_url, container_name=container_name)
        names: list[str] = []
        for blob in client.list_blobs(results_per_page=MAX_OBJECTS):
            names.append(blob.name)
            if len(names) >= MAX_OBJECTS:
                break
        return names

    async def _list_gcp(self, bucket_name: str) -> list[str]:
        from google.cloud import storage as gcs
        from google.auth.credentials import AnonymousCredentials

        client = gcs.Client(credentials=AnonymousCredentials(), project="none")
        bucket = client.bucket(bucket_name)
        return [blob.name for blob in bucket.list_blobs(max_results=MAX_OBJECTS)]

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
            log.info("Skipping file_lister -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        public_assets = await self._get_public_cloud_assets(target_id)
        if not public_assets:
            log.info("No public cloud assets to list")
            return stats

        prober = BucketProberTool()

        for ca in public_assets:
            if not ca.url:
                continue

            bucket_name = prober.extract_bucket_name(ca.url, ca.provider)
            if not bucket_name:
                continue

            object_names: list[str] = []
            try:
                if ca.provider == "aws":
                    object_names = await self._list_s3(bucket_name)
                elif ca.provider == "azure":
                    object_names = await self._list_azure(ca.url, bucket_name)
                elif ca.provider == "gcp":
                    object_names = await self._list_gcp(bucket_name)
            except Exception as exc:
                log.error(f"File listing failed for {ca.url}: {exc}")
                continue

            stats["found"] += len(object_names)
            sensitive_files: list[str] = []

            for name in object_names:
                if self.is_sensitive(name):
                    sensitive_files.append(name)
                    stats["in_scope"] += 1

                    severity = self.severity_for_file(name)
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=None,
                        severity=severity,
                        title=f"Sensitive file in public {ca.provider.upper()} bucket",
                        description=(
                            f"File '{name}' found in public bucket {bucket_name} "
                            f"({ca.url}). File type indicates potential sensitive data."
                        ),
                        poc=f"{ca.url}/{name}",
                    )
                    stats["new"] += 1

            if sensitive_files:
                existing_findings = ca.findings or {}
                existing_findings["sensitive_files"] = sensitive_files
                await self._save_cloud_asset(
                    target_id=target_id,
                    provider=ca.provider,
                    asset_type=ca.asset_type,
                    url=ca.url,
                    is_public=True,
                    findings=existing_findings,
                )

        await self.update_tool_state(target_id, container_name)
        log.info("file_lister complete", extra=stats)
        return stats
