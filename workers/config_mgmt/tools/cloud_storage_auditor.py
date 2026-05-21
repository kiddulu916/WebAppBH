"""Cloud storage configuration auditor — WSTG-CONF-11."""

from __future__ import annotations

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


class CloudStorageAuditor(ConfigMgmtTool):
    """Audit cloud storage configurations — WSTG-CONF-11."""

    name = "cloud_storage_auditor"

    def build_command(self, target, headers=None):
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")
