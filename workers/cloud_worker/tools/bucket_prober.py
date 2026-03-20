"""BucketProberTool -- Stage 2 unified cloud permission probing.

Checks AWS S3, Azure Blob, and GCP Storage resources for public
read/write/ACL permissions using anonymous SDK calls.  Dispatches
internally based on the ``provider`` field of each CloudAsset.
"""

from __future__ import annotations

from urllib.parse import urlparse

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool
from workers.cloud_worker.concurrency import WeightClass

logger = setup_logger("bucket-prober")

PROBE_TIMEOUT = 30


class BucketProberTool(CloudTestTool):
    """Probe cloud resources for public access permissions."""

    name = "bucket_prober"
    weight_class = WeightClass.HEAVY

    def extract_bucket_name(self, url: str, provider: str) -> str:
        """Extract bucket/container name from a cloud URL."""
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")

        if provider == "aws":
            host = parsed.hostname or ""
            if host.endswith(".amazonaws.com") and host != "s3.amazonaws.com":
                return host.split(".s3")[0]
            path_parts = parsed.path.strip("/").split("/")
            return path_parts[0] if path_parts else ""

        if provider == "azure":
            path_parts = parsed.path.strip("/").split("/")
            return path_parts[0] if path_parts else ""

        if provider == "gcp":
            path_parts = parsed.path.strip("/").split("/")
            return path_parts[0] if path_parts else ""

        return ""

    @staticmethod
    def severity_for_access(access_level: str) -> str:
        """Map access level to vulnerability severity."""
        return {
            "write": "critical",
            "read": "high",
            "list": "high",
        }.get(access_level, "info")

    async def _probe_s3(self, bucket_name: str) -> dict:
        """Probe an S3 bucket for public access using anonymous boto3 client."""
        import botocore.session
        from botocore import UNSIGNED
        from botocore.config import Config

        findings: dict = {"readable": False, "writable": False, "acl_public": False, "details": {}}
        session = botocore.session.get_session()
        client = session.create_client("s3", config=Config(signature_version=UNSIGNED))

        try:
            resp = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            findings["readable"] = True
            findings["details"]["object_count_sample"] = resp.get("KeyCount", 0)
        except Exception:
            pass

        try:
            acl = client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings["acl_public"] = True
                    perm = grant.get("Permission", "")
                    if perm in ("WRITE", "FULL_CONTROL"):
                        findings["writable"] = True
        except Exception:
            pass

        client.close()
        return findings

    async def _probe_azure(self, url: str, container_name: str) -> dict:
        """Probe an Azure blob container for public access."""
        from azure.storage.blob import ContainerClient
        from azure.core.exceptions import HttpResponseError

        findings: dict = {"readable": False, "writable": False, "public_access": None, "details": {}}
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        account_url = f"{parsed.scheme}://{parsed.hostname}"

        try:
            client = ContainerClient(account_url=account_url, container_name=container_name)
            props = client.get_container_properties()
            pub_access = props.get("public_access")
            findings["public_access"] = str(pub_access) if pub_access else None
            findings["readable"] = pub_access is not None

            if findings["readable"]:
                blobs = []
                for blob in client.list_blobs(results_per_page=1):
                    blobs.append(blob.name)
                    break
                findings["details"]["has_blobs"] = len(blobs) > 0
        except HttpResponseError:
            pass
        except Exception:
            pass

        return findings

    async def _probe_gcp(self, bucket_name: str) -> dict:
        """Probe a GCP Storage bucket for public access."""
        from google.cloud import storage as gcs
        from google.auth.credentials import AnonymousCredentials

        findings: dict = {"readable": False, "writable": False, "details": {}}

        try:
            client = gcs.Client(credentials=AnonymousCredentials(), project="none")
            bucket = client.bucket(bucket_name)
            blobs = list(bucket.list_blobs(max_results=1))
            findings["readable"] = True
            findings["details"]["has_objects"] = len(blobs) > 0
        except Exception:
            pass

        return findings

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
            log.info("Skipping bucket_prober -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        cloud_assets = await self._get_cloud_assets(target_id)
        stats["found"] = len(cloud_assets)

        if not cloud_assets:
            log.info("No cloud assets to probe")
            return stats

        for ca in cloud_assets:
            if not ca.url:
                continue

            scope_result = scope_manager.is_in_scope(ca.url)
            if not scope_result.in_scope:
                continue

            stats["in_scope"] += 1
            bucket_name = self.extract_bucket_name(ca.url, ca.provider)
            if not bucket_name:
                continue

            findings: dict = {}
            try:
                if ca.provider == "aws":
                    findings = await self._probe_s3(bucket_name)
                elif ca.provider == "azure":
                    findings = await self._probe_azure(ca.url, bucket_name)
                elif ca.provider == "gcp":
                    findings = await self._probe_gcp(bucket_name)
            except Exception as exc:
                log.error(f"Probe failed for {ca.url}: {exc}")
                continue

            is_public = findings.get("readable", False) or findings.get("acl_public", False)

            await self._save_cloud_asset(
                target_id=target_id,
                provider=ca.provider,
                asset_type=ca.asset_type,
                url=ca.url,
                is_public=is_public,
                findings=findings,
            )

            if findings.get("writable"):
                access = "write"
            elif findings.get("readable"):
                access = "read"
            else:
                continue

            stats["new"] += 1
            severity = self.severity_for_access(access)

            await self._save_vulnerability(
                target_id=target_id,
                asset_id=None,
                severity=severity,
                title=f"Public {ca.provider.upper()} {ca.asset_type}: {access} access",
                description=(
                    f"Cloud resource {ca.url} has public {access} access. "
                    f"Bucket: {bucket_name}. Details: {findings}"
                ),
                poc=ca.url,
            )

        await self.update_tool_state(target_id, container_name)
        log.info("bucket_prober complete", extra=stats)
        return stats
