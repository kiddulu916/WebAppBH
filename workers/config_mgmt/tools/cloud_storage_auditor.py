"""Cloud storage configuration auditor — WSTG-CONF-11."""

from __future__ import annotations

import json
import re
from datetime import datetime

from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf11")

_SECTION_ID = "WSTG-CONF-11"

# ── Compiled regex patterns ───────────────────────────────────────────────────

_S3_PATTERNS = [
    # Virtual-hosted: bucket.s3[-region].amazonaws.com
    re.compile(
        r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][\w\-]+)?\.amazonaws\.com",
        re.IGNORECASE,
    ),
    # Path-style: s3[-region].amazonaws.com/bucket
    re.compile(
        r"s3(?:[.\-][\w\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])",
        re.IGNORECASE,
    ),
    # Website endpoint: bucket.s3-website[-.]region.amazonaws.com
    re.compile(
        r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-website[-\.][\w\-]+\.amazonaws\.com",
        re.IGNORECASE,
    ),
]

_AZURE_PATTERNS = [
    # account.{blob|file|queue|table}.core.windows.net[/container]
    re.compile(
        r"([a-z0-9][a-z0-9\-]{1,22}[a-z0-9])"
        r"\.(?:blob|file|queue|table)\.core\.windows\.net"
        r"(?:/([a-z0-9][a-z0-9\-]{0,62}))?",
        re.IGNORECASE,
    ),
]

_GCS_PATTERNS = [
    # bucket.storage.googleapis.com
    re.compile(
        r"([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])\.storage\.googleapis\.com",
        re.IGNORECASE,
    ),
    # storage.googleapis.com/bucket  OR  storage.cloud.google.com/bucket
    re.compile(
        r"storage\.(?:googleapis\.com|cloud\.google\.com)"
        r"/([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])",
        re.IGNORECASE,
    ),
]


# ── Extraction ────────────────────────────────────────────────────────────────

def _extract_storage_refs(body: str, provider: str) -> list[str]:
    """Return all raw matched strings for the given provider found in body.

    provider must be one of: "s3", "azure", "gcs".
    Returns full match strings (group 0) — normalization is a separate step.
    """
    patterns = {"s3": _S3_PATTERNS, "azure": _AZURE_PATTERNS, "gcs": _GCS_PATTERNS}.get(
        provider, []
    )
    results: list[str] = []
    for pat in patterns:
        for m in pat.finditer(body):
            results.append(m.group(0))
    return results


# ── Normalization ─────────────────────────────────────────────────────────────

def _normalize_s3_ref(raw: str) -> tuple[str, str | None] | None:
    """Parse a raw S3 match string into (bucket_name, region | None).

    Returns None if raw does not match any known S3 URL format.
    """
    raw = raw.lower().strip()
    # Virtual-hosted, no region: bucket.s3.amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), None
    # Virtual-hosted, with region: bucket.s3[-.]region.amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-]([\w\-]+)\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), m.group(2)
    # Path-style: s3[-.]region.amazonaws.com/bucket or s3.amazonaws.com/bucket
    m = re.match(
        r"^s3(?:[.\-]([\w\-]+))?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])$",
        raw,
    )
    if m:
        return m.group(2), m.group(1)
    # Website endpoint: bucket.s3-website[-.]region.amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-website[-\.][\w\-]+\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), None
    return None


def _normalize_azure_ref(raw: str) -> tuple[str, str | None] | None:
    """Parse a raw Azure match string into (account, container | None).

    Returns None if raw does not match any known Azure storage URL format.
    """
    raw = raw.lower().strip()
    m = re.match(
        r"^([a-z0-9][a-z0-9\-]{1,22}[a-z0-9])"
        r"\.(?:blob|file|queue|table)\.core\.windows\.net"
        r"(?:/([a-z0-9][a-z0-9\-]{0,62}))?$",
        raw,
    )
    if m:
        return m.group(1), m.group(2) or None
    return None


def _normalize_gcs_ref(raw: str) -> str | None:
    """Parse a raw GCS match string into a bucket name.

    Returns None if raw does not match any known GCS URL format.
    """
    raw = raw.lower().strip()
    # bucket.storage.googleapis.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])\.storage\.googleapis\.com$", raw
    )
    if m:
        return m.group(1)
    # storage.googleapis.com/bucket  OR  storage.cloud.google.com/bucket
    m = re.match(
        r"^storage\.(?:googleapis\.com|cloud\.google\.com)"
        r"/([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])$",
        raw,
    )
    if m:
        return m.group(1)
    return None


# ── s3scanner ─────────────────────────────────────────────────────────────────

def _parse_s3scanner_output(text: str) -> list[dict]:
    """Parse s3scanner JSON file output into a list of normalised result dicts.

    Handles both s3scanner v1 ('bucket' key) and v2 ('name' key) field names.
    Returns [] on empty input or JSON parse failure.
    """
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        entries = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        results = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            results.append({
                "bucket": (entry["name"] if entry.get("name") else entry.get("bucket", "")),
                "exists": bool(entry.get("exists", False)),
                "listable": bool(
                    entry.get("objects_listable", entry.get("listable", False))
                ),
                "readable": bool(
                    entry.get("objects_readable", entry.get("readable", False))
                ),
                "writable": bool(
                    entry.get("objects_writable", entry.get("writable", False))
                ),
            })
        return results
    except (json.JSONDecodeError, ValueError):
        return []


def _classify_s3scanner_result(entry: dict) -> dict | None:
    """Convert one parsed s3scanner entry into a vulnerability or observation dict.

    Returns None only when the entry has no useful signal (malformed).
    """
    bucket = entry.get("bucket", "")
    location = f"https://{bucket}.s3.amazonaws.com"

    if not entry.get("exists"):
        return {
            "observation": {
                "type": "cloud_storage",
                "value": f"s3_bucket_not_found: {bucket}",
                "details": {
                    "provider": "aws_s3",
                    "bucket": bucket,
                    "note": "Bucket does not exist — potential unclaimed resource",
                },
            }
        }

    if entry.get("writable"):
        return {
            "vulnerability": {
                "name": f"Publicly writable S3 bucket: {bucket}",
                "severity": "critical",
                "description": (
                    f"S3 bucket '{bucket}' allows anonymous write access. "
                    f"An attacker can upload arbitrary files to serve malicious content "
                    f"or exfiltrate data."
                ),
                "location": location,
                "section_id": _SECTION_ID,
            }
        }

    if entry.get("listable"):
        return {
            "vulnerability": {
                "name": f"Publicly listable S3 bucket: {bucket}",
                "severity": "high",
                "description": (
                    f"S3 bucket '{bucket}' allows anonymous listing of its contents. "
                    f"Sensitive files may be enumerated and downloaded."
                ),
                "location": location,
                "section_id": _SECTION_ID,
            }
        }

    if entry.get("readable"):
        return {
            "vulnerability": {
                "name": f"Publicly readable S3 bucket: {bucket}",
                "severity": "medium",
                "description": (
                    f"S3 bucket '{bucket}' allows anonymous read access to individual "
                    f"objects but does not expose a directory listing."
                ),
                "location": location,
                "section_id": _SECTION_ID,
            }
        }

    # Exists but fully restricted
    return {
        "observation": {
            "type": "cloud_storage",
            "value": f"s3_bucket_restricted: {bucket}",
            "details": {
                "provider": "aws_s3",
                "bucket": bucket,
                "note": "Bucket exists but access is fully restricted",
            },
        }
    }


# ── cloud_enum ────────────────────────────────────────────────────────────────

def _parse_cloud_enum_output(text: str) -> dict[str, list[str]]:
    """Parse cloud_enum stdout into a dict mapping provider to raw URL list.

    cloud_enum prefixes each discovered resource with '[+] AWS:', '[+] Azure:',
    or '[+] GCP:'. Lines not matching any of these prefixes are silently skipped.
    Returns {"s3": [...], "azure": [...], "gcs": [...]}.
    """
    result: dict[str, list[str]] = {"s3": [], "azure": [], "gcs": []}
    for line in text.splitlines():
        lower = line.lower()
        for prefix, key in (("[+] aws:", "s3"), ("[+] azure:", "azure"), ("[+] gcp:", "gcs")):
            if prefix in lower:
                idx = lower.index(prefix) + len(prefix)
                url = line[idx:].strip()
                if url:
                    result[key].append(url)
                break
    return result


# ── azcopy / Azure ────────────────────────────────────────────────────────────

def _parse_azcopy_output(text: str) -> list[dict]:
    """Parse azcopy list stdout into [{container_url: str, accessible: bool}].

    azcopy v10 prefixes each listed object with 'INFO:'.
    Error responses contain 'RESPONSE Status: 4xx' or known failure keywords.
    Empty input is treated as inaccessible (no output = command failed or no access).
    """
    text = text.strip()
    if not text:
        return [{"container_url": "", "accessible": False}]
    error_markers = [
        "RESPONSE Status: 4",
        "RESPONSE Status: 5",
        "AuthorizationFailure",
        "failed to authenticate",
        "does not exist",
        "ResourceNotFound",
    ]
    has_error = any(marker in text for marker in error_markers)
    return [{"container_url": "", "accessible": not has_error}]


def _classify_azure_probe(
    container_url: str,
    list_accessible: bool,
    head_readable: bool,
    write_status: int,
) -> dict | None:
    """Classify an Azure Blob container probe result into a finding dict.

    Priority order: write > list > read > None (fully restricted).
    Returns None when the container appears fully restricted.
    """
    if write_status in (200, 201):
        access = "write and list" if list_accessible else "write"
        return {
            "vulnerability": {
                "name": f"Publicly writable Azure Blob container: {container_url}",
                "severity": "critical",
                "description": (
                    f"Azure Blob container at {container_url} allows anonymous {access} "
                    f"access. An attacker can upload arbitrary files."
                ),
                "location": container_url,
                "section_id": _SECTION_ID,
            }
        }

    if list_accessible:
        return {
            "vulnerability": {
                "name": f"Publicly listable Azure Blob container: {container_url}",
                "severity": "high",
                "description": (
                    f"Azure Blob container at {container_url} allows anonymous listing "
                    f"of its contents."
                ),
                "location": container_url,
                "section_id": _SECTION_ID,
            }
        }

    if head_readable:
        return {
            "vulnerability": {
                "name": f"Publicly readable Azure Blob container: {container_url}",
                "severity": "medium",
                "description": (
                    f"Azure Blob container at {container_url} allows anonymous read "
                    f"access to individual objects but does not expose a directory listing."
                ),
                "location": container_url,
                "section_id": _SECTION_ID,
            }
        }

    return None


class CloudStorageAuditor(ConfigMgmtTool):
    """Audit cloud storage configurations — WSTG-CONF-11."""

    name = "cloud_storage_auditor"

    def build_command(self, target, headers=None):
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")
