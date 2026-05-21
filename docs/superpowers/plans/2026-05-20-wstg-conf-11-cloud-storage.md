# WSTG-CONF-11 Cloud Storage Auditor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `CloudStorageAuditor` from a Python-subprocess stub into a proper `execute()` override that uses s3scanner, azcopy, cloud_enum, and aiohttp to audit AWS S3, Azure Blob, and GCS resources for public list/read/write misconfigurations.

**Architecture:** Five-phase pipeline — (1) extract cloud storage references from the DB and a live crawl of the target, (2) enumerate additional candidates with cloud_enum, (3) scan S3 buckets with s3scanner, (4) probe Azure Blob containers with azcopy + aiohttp write test, (5) probe GCS buckets with aiohttp. All detection logic lives in pure module-level functions; `execute()` owns only I/O and orchestration.

**Tech Stack:** Python 3.10, aiohttp, s3scanner (Go binary), azcopy v10 (pre-built binary), cloud-enum (pip), SQLAlchemy async, pytest (sync-only unit tests).

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| **Overwrite** | `workers/config_mgmt/tools/cloud_storage_auditor.py` | Full rewrite — regex constants, 12 pure helpers, `CloudStorageAuditor.execute()` |
| **Create** | `tests/unit/config_mgmt/test_cloud_storage_auditor.py` | Sync unit tests for every pure helper function |
| **Modify** | `docker/Dockerfile.config_mgmt` | Add s3scanner Go install, azcopy tar.gz download, pip install cloud-enum |

No changes to `pipeline.py`, `playbooks.py`, `worker-stages.ts`, `concurrency.py`, or `tools/__init__.py`.

---

## Task 1: Module skeleton + regex constants + extraction + normalization

**Files:**
- Create: `tests/unit/config_mgmt/test_cloud_storage_auditor.py`
- Overwrite: `workers/config_mgmt/tools/cloud_storage_auditor.py`

- [ ] **Step 1: Write failing tests for extraction and normalization**

Create `tests/unit/config_mgmt/test_cloud_storage_auditor.py`:

```python
"""Unit tests for CloudStorageAuditor pure helpers (WSTG-CONF-11)."""
import json

from workers.config_mgmt.tools.cloud_storage_auditor import (
    _SECTION_ID,
    _extract_storage_refs,
    _normalize_s3_ref,
    _normalize_azure_ref,
    _normalize_gcs_ref,
)


# ── _SECTION_ID ──────────────────────────────────────────────────────────────

def test_section_id():
    assert _SECTION_ID == "WSTG-CONF-11"


# ── _extract_storage_refs ────────────────────────────────────────────────────

def test_extract_s3_virtual_hosted():
    body = "Check https://my-bucket.s3.amazonaws.com/file.txt for assets"
    result = _extract_storage_refs(body, "s3")
    assert any("my-bucket" in r for r in result)


def test_extract_s3_with_region():
    body = "https://my-bucket.s3.us-east-1.amazonaws.com/key"
    result = _extract_storage_refs(body, "s3")
    assert any("my-bucket" in r for r in result)


def test_extract_s3_path_style():
    body = "stored at https://s3.amazonaws.com/my-bucket/key"
    result = _extract_storage_refs(body, "s3")
    assert any("my-bucket" in r for r in result)


def test_extract_azure_blob():
    body = "https://myaccount.blob.core.windows.net/mycontainer/file"
    result = _extract_storage_refs(body, "azure")
    assert any("myaccount" in r for r in result)


def test_extract_azure_file_service():
    body = "https://myaccount.file.core.windows.net/share"
    result = _extract_storage_refs(body, "azure")
    assert any("myaccount" in r for r in result)


def test_extract_gcs_googleapis():
    body = "https://storage.googleapis.com/my-gcs-bucket/key"
    result = _extract_storage_refs(body, "gcs")
    assert any("my-gcs-bucket" in r for r in result)


def test_extract_gcs_subdomain():
    body = "https://my-gcs-bucket.storage.googleapis.com/key"
    result = _extract_storage_refs(body, "gcs")
    assert any("my-gcs-bucket" in r for r in result)


def test_extract_no_match_returns_empty():
    body = "Nothing cloud-related here, just a normal webpage."
    assert _extract_storage_refs(body, "s3") == []
    assert _extract_storage_refs(body, "azure") == []
    assert _extract_storage_refs(body, "gcs") == []


def test_extract_multiple_s3_refs():
    body = "bucket1.s3.amazonaws.com and bucket2.s3.amazonaws.com"
    result = _extract_storage_refs(body, "s3")
    assert len(result) == 2


# ── _normalize_s3_ref ─────────────────────────────────────────────────────────

def test_normalize_s3_virtual_hosted_with_region():
    result = _normalize_s3_ref("my-bucket.s3.us-east-1.amazonaws.com")
    assert result is not None
    assert result[0] == "my-bucket"
    assert result[1] == "us-east-1"


def test_normalize_s3_virtual_hosted_no_region():
    result = _normalize_s3_ref("my-bucket.s3.amazonaws.com")
    assert result is not None
    assert result[0] == "my-bucket"
    assert result[1] is None


def test_normalize_s3_path_style():
    result = _normalize_s3_ref("s3.amazonaws.com/my-bucket")
    assert result is not None
    assert result[0] == "my-bucket"


def test_normalize_s3_website_endpoint():
    result = _normalize_s3_ref("my-bucket.s3-website-us-east-1.amazonaws.com")
    assert result is not None
    assert result[0] == "my-bucket"


def test_normalize_s3_invalid_returns_none():
    assert _normalize_s3_ref("not-a-bucket") is None
    assert _normalize_s3_ref("") is None


# ── _normalize_azure_ref ──────────────────────────────────────────────────────

def test_normalize_azure_with_container():
    result = _normalize_azure_ref("myaccount.blob.core.windows.net/mycontainer")
    assert result is not None
    assert result[0] == "myaccount"
    assert result[1] == "mycontainer"


def test_normalize_azure_no_container():
    result = _normalize_azure_ref("myaccount.blob.core.windows.net")
    assert result is not None
    assert result[0] == "myaccount"
    assert result[1] is None


def test_normalize_azure_file_service():
    result = _normalize_azure_ref("myaccount.file.core.windows.net")
    assert result is not None
    assert result[0] == "myaccount"


def test_normalize_azure_queue_service():
    result = _normalize_azure_ref("myaccount.queue.core.windows.net")
    assert result is not None
    assert result[0] == "myaccount"


def test_normalize_azure_invalid_returns_none():
    assert _normalize_azure_ref("not-azure.example.com") is None
    assert _normalize_azure_ref("") is None


# ── _normalize_gcs_ref ────────────────────────────────────────────────────────

def test_normalize_gcs_storage_googleapis():
    result = _normalize_gcs_ref("storage.googleapis.com/my-gcs-bucket")
    assert result == "my-gcs-bucket"


def test_normalize_gcs_subdomain_style():
    result = _normalize_gcs_ref("my-gcs-bucket.storage.googleapis.com")
    assert result == "my-gcs-bucket"


def test_normalize_gcs_cloud_google():
    result = _normalize_gcs_ref("storage.cloud.google.com/my-gcs-bucket")
    assert result == "my-gcs-bucket"


def test_normalize_gcs_invalid_returns_none():
    assert _normalize_gcs_ref("notgcs.example.com") is None
    assert _normalize_gcs_ref("") is None
```

- [ ] **Step 2: Run tests — expect ImportError (module doesn't exist yet)**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: `ImportError: cannot import name '_SECTION_ID' from 'workers.config_mgmt.tools.cloud_storage_auditor'` (or `ModuleNotFoundError`). That is the failing state.

- [ ] **Step 3: Write the module skeleton with constants and pure helpers**

Overwrite `workers/config_mgmt/tools/cloud_storage_auditor.py` with:

```python
"""Cloud storage configuration auditor — WSTG-CONF-11."""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse
from xml.etree import ElementTree

import aiohttp
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
    # Virtual-hosted: bucket.s3[-region].amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-]([\w\-]+))?\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), m.group(2)
    # Path-style: s3[-region].amazonaws.com/bucket
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
        r"(?:/([a-z0-9][a-z0-9\-]{0,62}))?",
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
```

- [ ] **Step 4: Run tests — expect all to pass**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: all tests PASS. If any regex normalization test fails, check the regex in `_normalize_s3_ref` / `_normalize_azure_ref` / `_normalize_gcs_ref` — common pitfall is the `$` anchor blocking matches with trailing slashes, so ensure the test bodies strip trailing slashes before passing to normalization.

- [ ] **Step 5: Commit**

```
git add workers/config_mgmt/tools/cloud_storage_auditor.py \
        tests/unit/config_mgmt/test_cloud_storage_auditor.py
git commit -m "feat(conf11): add regex constants, extraction, and normalization helpers"
```

---

## Task 2: s3scanner output parsing and classification

**Files:**
- Modify: `tests/unit/config_mgmt/test_cloud_storage_auditor.py` (append)
- Modify: `workers/config_mgmt/tools/cloud_storage_auditor.py` (append before the class)

- [ ] **Step 1: Append failing tests for s3scanner parsing**

Add to the bottom of `tests/unit/config_mgmt/test_cloud_storage_auditor.py`:

```python
from workers.config_mgmt.tools.cloud_storage_auditor import (
    _parse_s3scanner_output,
    _classify_s3scanner_result,
)


# ── _parse_s3scanner_output ───────────────────────────────────────────────────

def test_parse_s3scanner_empty_returns_empty():
    assert _parse_s3scanner_output("") == []


def test_parse_s3scanner_malformed_json_returns_empty():
    assert _parse_s3scanner_output("not json {{{{") == []


def test_parse_s3scanner_writable_bucket():
    data = json.dumps([{
        "name": "test-bucket",
        "exists": True,
        "objects_listable": True,
        "objects_readable": True,
        "objects_writable": True,
    }])
    result = _parse_s3scanner_output(data)
    assert len(result) == 1
    assert result[0]["bucket"] == "test-bucket"
    assert result[0]["exists"] is True
    assert result[0]["listable"] is True
    assert result[0]["readable"] is True
    assert result[0]["writable"] is True


def test_parse_s3scanner_nonexistent_bucket():
    data = json.dumps([{
        "name": "ghost-bucket",
        "exists": False,
        "objects_listable": False,
        "objects_readable": False,
        "objects_writable": False,
    }])
    result = _parse_s3scanner_output(data)
    assert result[0]["exists"] is False
    assert result[0]["writable"] is False


def test_parse_s3scanner_accepts_bucket_field_alias():
    """s3scanner v1 used 'bucket' instead of 'name'."""
    data = json.dumps([{"bucket": "legacy-bucket", "exists": True}])
    result = _parse_s3scanner_output(data)
    assert result[0]["bucket"] == "legacy-bucket"


def test_parse_s3scanner_multiple_entries():
    data = json.dumps([
        {"name": "bucket-a", "exists": True, "objects_writable": True},
        {"name": "bucket-b", "exists": True, "objects_writable": False},
    ])
    result = _parse_s3scanner_output(data)
    assert len(result) == 2


# ── _classify_s3scanner_result ────────────────────────────────────────────────

def test_classify_s3_writable_is_critical():
    entry = {"bucket": "test", "exists": True, "listable": True, "readable": True, "writable": True}
    result = _classify_s3scanner_result(entry)
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_s3_listable_only_is_high():
    entry = {"bucket": "test", "exists": True, "listable": True, "readable": True, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_s3_readable_only_is_medium():
    entry = {"bucket": "test", "exists": True, "listable": False, "readable": True, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert result["vulnerability"]["severity"] == "medium"


def test_classify_s3_restricted_is_observation():
    entry = {"bucket": "test", "exists": True, "listable": False, "readable": False, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert result is not None
    assert "observation" in result


def test_classify_s3_not_exists_is_observation():
    entry = {"bucket": "ghost", "exists": False, "listable": False, "readable": False, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert "observation" in result
    assert "not_found" in result["observation"]["value"]


def test_classify_s3_always_sets_section_id():
    entry = {"bucket": "test", "exists": True, "listable": True, "readable": True, "writable": True}
    result = _classify_s3scanner_result(entry)
    assert result["vulnerability"]["section_id"] == _SECTION_ID
```

- [ ] **Step 2: Run tests — expect failures on the new tests**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v -k "s3scanner or classify_s3"
```

Expected: `ImportError` or `NameError` for `_parse_s3scanner_output` and `_classify_s3scanner_result`.

- [ ] **Step 3: Implement the two functions**

Add before the `CloudStorageAuditor` class in `workers/config_mgmt/tools/cloud_storage_auditor.py`:

```python
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
                "bucket":   entry.get("name") or entry.get("bucket", ""),
                "exists":   bool(entry.get("exists", False)),
                "listable": bool(
                    entry.get("objects_listable") or entry.get("listable", False)
                ),
                "readable": bool(
                    entry.get("objects_readable") or entry.get("readable", False)
                ),
                "writable": bool(
                    entry.get("objects_writable") or entry.get("writable", False)
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
```

- [ ] **Step 4: Run tests — expect all to pass**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```
git add workers/config_mgmt/tools/cloud_storage_auditor.py \
        tests/unit/config_mgmt/test_cloud_storage_auditor.py
git commit -m "feat(conf11): add s3scanner output parsing and classification helpers"
```

---

## Task 3: cloud_enum output parsing

**Files:**
- Modify: `tests/unit/config_mgmt/test_cloud_storage_auditor.py` (append)
- Modify: `workers/config_mgmt/tools/cloud_storage_auditor.py` (append before class)

- [ ] **Step 1: Append failing tests**

Add to `tests/unit/config_mgmt/test_cloud_storage_auditor.py`:

```python
from workers.config_mgmt.tools.cloud_storage_auditor import _parse_cloud_enum_output


# ── _parse_cloud_enum_output ──────────────────────────────────────────────────

def test_parse_cloud_enum_empty_returns_empty_lists():
    result = _parse_cloud_enum_output("")
    assert result == {"s3": [], "azure": [], "gcs": []}


def test_parse_cloud_enum_aws_line():
    text = "[+] AWS: https://exampleco.s3.amazonaws.com"
    result = _parse_cloud_enum_output(text)
    assert len(result["s3"]) == 1
    assert "amazonaws.com" in result["s3"][0]


def test_parse_cloud_enum_azure_line():
    text = "[+] Azure: https://exampleco.blob.core.windows.net"
    result = _parse_cloud_enum_output(text)
    assert len(result["azure"]) == 1
    assert "blob.core.windows.net" in result["azure"][0]


def test_parse_cloud_enum_gcp_line():
    text = "[+] GCP: https://storage.googleapis.com/exampleco"
    result = _parse_cloud_enum_output(text)
    assert len(result["gcs"]) == 1
    assert "googleapis.com" in result["gcs"][0]


def test_parse_cloud_enum_unknown_lines_skipped():
    text = "Scanning...\n[+] AWS: https://exampleco.s3.amazonaws.com\nDone."
    result = _parse_cloud_enum_output(text)
    assert len(result["s3"]) == 1
    assert result["azure"] == []
    assert result["gcs"] == []


def test_parse_cloud_enum_multiple_providers():
    text = (
        "[+] AWS: https://exampleco.s3.amazonaws.com\n"
        "[+] Azure: https://exampleco.blob.core.windows.net\n"
        "[+] GCP: https://storage.googleapis.com/exampleco\n"
    )
    result = _parse_cloud_enum_output(text)
    assert len(result["s3"]) == 1
    assert len(result["azure"]) == 1
    assert len(result["gcs"]) == 1
```

- [ ] **Step 2: Run tests — expect ImportError on new imports**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v -k "cloud_enum"
```

Expected: `ImportError` for `_parse_cloud_enum_output`.

- [ ] **Step 3: Implement**

Add before the `CloudStorageAuditor` class:

```python
# ── cloud_enum ────────────────────────────────────────────────────────────────

def _parse_cloud_enum_output(text: str) -> dict[str, list[str]]:
    """Parse cloud_enum stdout into a dict mapping provider to raw URL list.

    cloud_enum prefixes each discovered resource with '[+] AWS:', '[+] Azure:',
    or '[+] GCP:'. Lines not matching any prefix are silently skipped.
    Returns {"s3": [...], "azure": [...], "gcs": [...]}.
    """
    result: dict[str, list[str]] = {"s3": [], "azure": [], "gcs": []}
    for line in text.splitlines():
        lower = line.lower()
        if "[+] aws:" in lower or "amazonaws.com" in lower:
            url = line.split(":", 1)[-1].strip()
            if url:
                result["s3"].append(url)
        elif "[+] azure:" in lower or "blob.core.windows.net" in lower:
            url = line.split(":", 1)[-1].strip()
            if url:
                result["azure"].append(url)
        elif "[+] gcp:" in lower or "googleapis.com" in lower:
            url = line.split(":", 1)[-1].strip()
            if url:
                result["gcs"].append(url)
    return result
```

- [ ] **Step 4: Run all tests**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```
git add workers/config_mgmt/tools/cloud_storage_auditor.py \
        tests/unit/config_mgmt/test_cloud_storage_auditor.py
git commit -m "feat(conf11): add cloud_enum output parser"
```

---

## Task 4: azcopy output parsing and Azure probe classification

**Files:**
- Modify: `tests/unit/config_mgmt/test_cloud_storage_auditor.py` (append)
- Modify: `workers/config_mgmt/tools/cloud_storage_auditor.py` (append before class)

- [ ] **Step 1: Append failing tests**

Add to `tests/unit/config_mgmt/test_cloud_storage_auditor.py`:

```python
from workers.config_mgmt.tools.cloud_storage_auditor import (
    _parse_azcopy_output,
    _classify_azure_probe,
)


# ── _parse_azcopy_output ──────────────────────────────────────────────────────

def test_parse_azcopy_accessible_when_info_lines_present():
    text = (
        "INFO: https://account.blob.core.windows.net/container/file.txt; "
        "Content Length: 100"
    )
    result = _parse_azcopy_output(text)
    assert len(result) == 1
    assert result[0]["accessible"] is True


def test_parse_azcopy_not_accessible_on_403():
    text = "RESPONSE Status: 403 Server failed to authenticate the request."
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_404():
    text = "RESPONSE Status: 404 The specified resource does not exist."
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_empty():
    result = _parse_azcopy_output("")
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_auth_failure():
    text = "AuthorizationFailure: Server failed to authenticate."
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


# ── _classify_azure_probe ─────────────────────────────────────────────────────

_AZURE_URL = "https://myaccount.blob.core.windows.net/mycontainer"


def test_classify_azure_write_success_is_critical():
    result = _classify_azure_probe(_AZURE_URL, True, True, 201)
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == _SECTION_ID


def test_classify_azure_list_only_is_high():
    result = _classify_azure_probe(_AZURE_URL, True, True, 403)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_azure_read_only_is_medium():
    result = _classify_azure_probe(_AZURE_URL, False, True, 403)
    assert result["vulnerability"]["severity"] == "medium"


def test_classify_azure_fully_restricted_returns_none():
    result = _classify_azure_probe(_AZURE_URL, False, False, 403)
    assert result is None


def test_classify_azure_write_without_list_is_critical():
    result = _classify_azure_probe(_AZURE_URL, False, False, 201)
    assert result["vulnerability"]["severity"] == "critical"
```

- [ ] **Step 2: Run tests — expect ImportError**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v -k "azcopy or azure_probe"
```

Expected: `ImportError`.

- [ ] **Step 3: Implement**

Add before the `CloudStorageAuditor` class:

```python
# ── azcopy / Azure ────────────────────────────────────────────────────────────

def _parse_azcopy_output(text: str) -> list[dict]:
    """Parse azcopy list stdout into [{container_url: str, accessible: bool}].

    azcopy v10 prefixes each listed object with 'INFO:'.
    Error responses contain 'RESPONSE Status: 4xx' or known failure keywords.
    An empty container that is publicly accessible will produce no INFO: lines
    but also no error markers — treat absence-of-error as accessible.
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
```

- [ ] **Step 4: Run all tests**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```
git add workers/config_mgmt/tools/cloud_storage_auditor.py \
        tests/unit/config_mgmt/test_cloud_storage_auditor.py
git commit -m "feat(conf11): add azcopy parser and Azure probe classifier"
```

---

## Task 5: GCS probe classification and write probe classification

**Files:**
- Modify: `tests/unit/config_mgmt/test_cloud_storage_auditor.py` (append)
- Modify: `workers/config_mgmt/tools/cloud_storage_auditor.py` (append before class)

- [ ] **Step 1: Append failing tests**

Add to `tests/unit/config_mgmt/test_cloud_storage_auditor.py`:

```python
from workers.config_mgmt.tools.cloud_storage_auditor import (
    _classify_gcs_probe,
    _classify_write_probe,
)


# ── _classify_gcs_probe ───────────────────────────────────────────────────────

_GCS_URL = "https://storage.googleapis.com/my-gcs-bucket"
_LIST_BODY = "<ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>"


def test_classify_gcs_listable_and_writable_is_critical():
    result = _classify_gcs_probe(_GCS_URL, _LIST_BODY, 200)
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == _SECTION_ID


def test_classify_gcs_listable_read_only_is_high():
    result = _classify_gcs_probe(_GCS_URL, _LIST_BODY, 403)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_gcs_not_listable_not_writable_returns_none():
    result = _classify_gcs_probe(_GCS_URL, "", 403)
    assert result is None


def test_classify_gcs_not_listable_but_writable_is_critical():
    result = _classify_gcs_probe(_GCS_URL, "", 200)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_gcs_contents_tag_also_detected():
    body = "<ListBucketResult><Contents></Contents></ListBucketResult>"
    result = _classify_gcs_probe(_GCS_URL, body, 403)
    assert result["vulnerability"]["severity"] == "high"


# ── _classify_write_probe ─────────────────────────────────────────────────────

def test_classify_write_s3_put_200_is_critical():
    result = _classify_write_probe("https://bucket.s3.amazonaws.com", "s3", 200)
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == _SECTION_ID


def test_classify_write_azure_put_201_is_critical():
    result = _classify_write_probe(
        "https://acc.blob.core.windows.net/c", "azure", 201
    )
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_write_403_returns_none():
    result = _classify_write_probe("https://bucket.s3.amazonaws.com", "s3", 403)
    assert result is None


def test_classify_write_404_returns_none():
    result = _classify_write_probe("https://bucket.s3.amazonaws.com", "s3", 404)
    assert result is None
```

- [ ] **Step 2: Run tests — expect ImportError**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v -k "gcs_probe or write_probe"
```

Expected: `ImportError`.

- [ ] **Step 3: Implement**

Add before the `CloudStorageAuditor` class:

```python
# ── GCS ───────────────────────────────────────────────────────────────────────

def _classify_gcs_probe(
    bucket_url: str,
    list_body: str,
    write_status: int,
) -> dict | None:
    """Classify a GCS bucket probe result into a finding dict.

    list_body is the raw HTTP response body from GET /?prefix=.
    Priority order: write > list > None.
    """
    is_listable = "ListBucketResult" in list_body or "<Contents>" in list_body

    if write_status in (200, 201):
        access = "write and list" if is_listable else "write"
        return {
            "vulnerability": {
                "name": f"Publicly writable GCS bucket: {bucket_url}",
                "severity": "critical",
                "description": (
                    f"GCS bucket at {bucket_url} allows anonymous {access} access. "
                    f"An attacker can upload arbitrary files."
                ),
                "location": bucket_url,
                "section_id": _SECTION_ID,
            }
        }

    if is_listable:
        return {
            "vulnerability": {
                "name": f"Publicly listable GCS bucket: {bucket_url}",
                "severity": "high",
                "description": (
                    f"GCS bucket at {bucket_url} allows anonymous listing of its contents."
                ),
                "location": bucket_url,
                "section_id": _SECTION_ID,
            }
        }

    return None


# ── Generic write probe ───────────────────────────────────────────────────────

def _classify_write_probe(url: str, provider: str, put_status: int) -> dict | None:
    """Classify a raw write probe (PUT) result.

    Used when the caller issues a PUT independently of the provider-specific
    scan flow. Returns None for any status other than 200 or 201.
    """
    if put_status in (200, 201):
        return {
            "vulnerability": {
                "name": f"Publicly writable {provider.upper()} storage: {url}",
                "severity": "critical",
                "description": (
                    f"The {provider} storage resource at {url} allows anonymous write "
                    f"access (HTTP PUT returned {put_status}). "
                    f"An attacker can upload arbitrary content."
                ),
                "location": url,
                "section_id": _SECTION_ID,
            }
        }
    return None
```

- [ ] **Step 4: Run all tests**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```
git add workers/config_mgmt/tools/cloud_storage_auditor.py \
        tests/unit/config_mgmt/test_cloud_storage_auditor.py
git commit -m "feat(conf11): add GCS probe classifier and generic write probe classifier"
```

---

## Task 6: `execute()` method

**Files:**
- Modify: `workers/config_mgmt/tools/cloud_storage_auditor.py` (replace the `CloudStorageAuditor` class body)

No new unit tests — `execute()` is async I/O. Correctness is verified by a successful import and a quick syntax check.

- [ ] **Step 1: Replace the CloudStorageAuditor class body**

In `workers/config_mgmt/tools/cloud_storage_auditor.py`, replace the entire `CloudStorageAuditor` class (keep everything above it) with:

```python
class CloudStorageAuditor(ConfigMgmtTool):
    """Audit cloud storage configurations — WSTG-CONF-11."""

    name = "cloud_storage_auditor"

    def build_command(self, target, headers=None):
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, tool=self.name)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0,
                "message": f"{self.name} started",
            })

            raw = target.target_value if hasattr(target, "target_value") else str(target)
            if "://" not in raw:
                raw = f"https://{raw}"
            parsed_url = urlparse(raw)
            target_domain = (parsed_url.netloc or parsed_url.path).split(":")[0].lower()
            org_name = target_domain.split(".")[0]
            base_url = raw.rstrip("/")

            if not scope_manager.is_in_scope(raw).in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # ── Phase 1: Extract ───────────────────────────────────────────
            s3_buckets: set[str] = set()
            azure_refs: set[tuple[str, str | None]] = set()
            gcs_buckets: set[str] = set()

            def _ingest(body: str) -> None:
                for raw_ref in _extract_storage_refs(body, "s3"):
                    r = _normalize_s3_ref(raw_ref)
                    if r:
                        s3_buckets.add(r[0])
                for raw_ref in _extract_storage_refs(body, "azure"):
                    r = _normalize_azure_ref(raw_ref)
                    if r:
                        azure_refs.add(r)
                for raw_ref in _extract_storage_refs(body, "gcs"):
                    r = _normalize_gcs_ref(raw_ref)
                    if r:
                        gcs_buckets.add(r)

            # Source A: DB assets
            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["url", "subdomain", "domain", "cloud_storage"]),
                )
                db_assets = [
                    a.asset_value
                    for a in (await session.execute(stmt)).scalars().all()
                ]
            for val in db_assets:
                _ingest(val)

            # Source B: Live crawl
            crawl_urls = [
                base_url,
                f"{base_url}/robots.txt",
                f"{base_url}/sitemap.xml",
                f"{base_url}/static/js/",
                f"{base_url}/assets/js/",
                f"{base_url}/js/",
            ]
            http_timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=http_timeout) as http:
                async def _fetch(url: str) -> str:
                    try:
                        async with http.get(url, ssl=False) as resp:
                            return await resp.text(errors="replace")
                    except Exception:
                        return ""

                bodies = await asyncio.gather(*[_fetch(u) for u in crawl_urls])
            for body in bodies:
                _ingest(body)

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 20,
                "message": (
                    f"{self.name}: extracted {len(s3_buckets)} S3, "
                    f"{len(azure_refs)} Azure, {len(gcs_buckets)} GCS refs"
                ),
            })

            # ── Phase 2: Enumerate (cloud_enum) ───────────────────────────
            try:
                enum_stdout = await self.run_subprocess(
                    ["cloud_enum", "-k", target_domain, "-k", org_name]
                )
                enum_results = _parse_cloud_enum_output(enum_stdout)
                for s3_url in enum_results["s3"]:
                    raw_host = s3_url.replace("https://", "").replace("http://", "").strip("/")
                    r = _normalize_s3_ref(raw_host)
                    if r:
                        s3_buckets.add(r[0])
                for az_url in enum_results["azure"]:
                    raw_host = az_url.replace("https://", "").replace("http://", "").strip("/")
                    r = _normalize_azure_ref(raw_host)
                    if r:
                        azure_refs.add(r)
                for gcs_url in enum_results["gcs"]:
                    raw_host = gcs_url.replace("https://", "").replace("http://", "").strip("/")
                    r = _normalize_gcs_ref(raw_host)
                    if r:
                        gcs_buckets.add(r)
            except FileNotFoundError:
                log.warning(f"{self.name}: cloud_enum not found, skipping Phase 2")
            except asyncio.TimeoutError:
                log.warning(f"{self.name}: cloud_enum timed out, skipping Phase 2")

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 35,
                "message": (
                    f"{self.name}: after enum — {len(s3_buckets)} S3, "
                    f"{len(azure_refs)} Azure, {len(gcs_buckets)} GCS"
                ),
            })

            if not s3_buckets and not azure_refs and not gcs_buckets:
                log.info(f"{self.name}: no cloud storage refs found, nothing to probe")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            all_findings: list[dict] = []

            # ── Phase 3: S3 Scan (s3scanner) ──────────────────────────────
            tmp_s3_in = tmp_s3_out = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", prefix="csa_s3_", delete=False
                ) as f:
                    f.write("\n".join(s3_buckets))
                    tmp_s3_in = f.name

                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", prefix="csa_s3out_", delete=False
                ) as f:
                    tmp_s3_out = f.name

                try:
                    await self.run_subprocess([
                        "s3scanner", "scan",
                        "--bucket-file", tmp_s3_in,
                        "--json-output", tmp_s3_out,
                    ])
                except FileNotFoundError:
                    log.warning(f"{self.name}: s3scanner not found, skipping Phase 3")
                except asyncio.TimeoutError:
                    log.warning(f"{self.name}: s3scanner timed out, skipping Phase 3")
                else:
                    if os.path.exists(tmp_s3_out):
                        with open(tmp_s3_out) as fh:
                            for entry in _parse_s3scanner_output(fh.read()):
                                finding = _classify_s3scanner_result(entry)
                                if finding:
                                    all_findings.append(finding)
            finally:
                for tmp in (tmp_s3_in, tmp_s3_out):
                    if tmp and os.path.exists(tmp):
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 55,
                "message": f"{self.name}: S3 scan done — {len(all_findings)} findings",
            })

            # ── Phase 4: Azure Scan (azcopy + aiohttp) ────────────────────
            probe_ts = int(time.time())
            probe_filename = f"bbh-probe-{probe_ts}.txt"

            # Expand (account, None) by enumerating containers via the XML API
            expanded_azure: set[tuple[str, str]] = set()
            probe_timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=probe_timeout) as http:
                for account, container in list(azure_refs):
                    if container is None:
                        try:
                            enum_url = (
                                f"https://{account}.blob.core.windows.net/?comp=list"
                            )
                            async with http.get(enum_url, ssl=False) as resp:
                                if resp.status == 200:
                                    body = await resp.text(errors="replace")
                                    try:
                                        root = ElementTree.fromstring(body)
                                        for name_el in root.iter("Name"):
                                            if name_el.text:
                                                expanded_azure.add(
                                                    (account, name_el.text)
                                                )
                                    except ElementTree.ParseError:
                                        pass
                        except Exception:
                            pass
                    else:
                        expanded_azure.add((account, container))

            for account, container in expanded_azure:
                c_url = (
                    f"https://{account}.blob.core.windows.net/{container}"
                )
                list_accessible = False
                head_readable = False
                write_status = 0

                try:
                    azcopy_out = await self.run_subprocess(["azcopy", "list", c_url])
                    results = _parse_azcopy_output(azcopy_out)
                    if results:
                        list_accessible = results[0]["accessible"]
                except FileNotFoundError:
                    log.warning(f"{self.name}: azcopy not found, skipping azcopy step")
                except asyncio.TimeoutError:
                    log.warning(f"{self.name}: azcopy timed out for {c_url}")

                if not list_accessible:
                    async with aiohttp.ClientSession(
                        timeout=probe_timeout
                    ) as http:
                        try:
                            async with http.head(
                                f"{c_url}/index.html", ssl=False
                            ) as resp:
                                head_readable = resp.status == 200
                        except Exception:
                            pass

                if list_accessible or head_readable:
                    async with aiohttp.ClientSession(
                        timeout=probe_timeout
                    ) as http:
                        try:
                            async with http.put(
                                f"{c_url}/{probe_filename}",
                                data=b"bbh",
                                ssl=False,
                            ) as resp:
                                write_status = resp.status
                                if write_status == 201:
                                    try:
                                        await http.delete(
                                            f"{c_url}/{probe_filename}", ssl=False
                                        )
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                finding = _classify_azure_probe(
                    c_url, list_accessible, head_readable, write_status
                )
                if finding:
                    all_findings.append(finding)

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 70,
                "message": f"{self.name}: Azure scan done — {len(all_findings)} findings",
            })

            # ── Phase 5: GCS Scan (aiohttp) ───────────────────────────────
            for bucket in gcs_buckets:
                b_url = f"https://storage.googleapis.com/{bucket}"
                list_body = ""
                write_status = 0

                async with aiohttp.ClientSession(timeout=probe_timeout) as http:
                    try:
                        async with http.get(
                            f"{b_url}/?prefix=", ssl=False
                        ) as resp:
                            if resp.status == 200:
                                list_body = await resp.text(errors="replace")
                    except Exception:
                        pass

                    if "ListBucketResult" in list_body or "<Contents>" in list_body:
                        try:
                            async with http.put(
                                f"{b_url}/{probe_filename}",
                                data=b"bbh",
                                ssl=False,
                            ) as resp:
                                write_status = resp.status
                                if write_status in (200, 201):
                                    try:
                                        await http.delete(
                                            f"{b_url}/{probe_filename}", ssl=False
                                        )
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                finding = _classify_gcs_probe(b_url, list_body, write_status)
                if finding:
                    all_findings.append(finding)

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 85,
                "message": f"{self.name}: GCS scan done — {len(all_findings)} findings",
            })

            # ── Persist ────────────────────────────────────────────────────
            seen_keys: set[tuple] = set()
            unique_findings: list[dict] = []
            for finding in all_findings:
                if "vulnerability" in finding:
                    v = finding["vulnerability"]
                    key = (v.get("location", ""), v.get("name", ""))
                elif "observation" in finding:
                    o = finding["observation"]
                    key = (o.get("type", ""), o.get("value", ""))
                else:
                    continue
                if key not in seen_keys:
                    seen_keys.add(key)
                    unique_findings.append(finding)

            found = len(unique_findings)
            new_count = in_scope_count = 0
            for item in unique_findings:
                inserted = await self._process_result(
                    item, scope_manager, target_id, log
                )
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                job = (await session.execute(stmt)).scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {
                "found": found,
                "in_scope": in_scope_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": (
                    f"{self.name}: {new_count} new, "
                    f"{in_scope_count} in scope, {found} total"
                ),
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
```

- [ ] **Step 2: Verify the module imports without error**

```
python -c "from workers.config_mgmt.tools.cloud_storage_auditor import CloudStorageAuditor; print('OK')"
```

Expected output: `OK`

- [ ] **Step 3: Run full unit test suite**

```
pytest tests/unit/config_mgmt/test_cloud_storage_auditor.py -v
```

Expected: all tests PASS. The `execute()` method is not exercised by these tests — they only cover pure helpers.

- [ ] **Step 4: Commit**

```
git add workers/config_mgmt/tools/cloud_storage_auditor.py
git commit -m "feat(conf11): implement CloudStorageAuditor.execute() — 5-phase cloud storage audit"
```

---

## Task 7: Dockerfile — add s3scanner, azcopy, cloud-enum

**Files:**
- Modify: `docker/Dockerfile.config_mgmt`

- [ ] **Step 1: Add s3scanner to the Go builder stage**

In `docker/Dockerfile.config_mgmt`, add `s3scanner` after the existing `nuclei` install:

```dockerfile
RUN go install github.com/sa7mon/s3scanner@latest
```

The Go builder stage should now read:

```dockerfile
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/haccer/subjack@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/sa7mon/s3scanner@latest
```

- [ ] **Step 2: Copy s3scanner binary in the runtime stage**

Add `s3scanner` to the Go binaries COPY block:

```dockerfile
COPY --from=go-builder /go/bin/ffuf     /usr/local/bin/
COPY --from=go-builder /go/bin/subjack  /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei   /usr/local/bin/
COPY --from=go-builder /go/bin/s3scanner /usr/local/bin/
```

- [ ] **Step 3: Download and install azcopy**

Add after the Go binaries COPY block:

```dockerfile
# azcopy v10 — pre-built Linux binary from Microsoft
RUN wget -q -O /tmp/azcopy.tar.gz https://aka.ms/downloadazcopy-v10-linux && \
    tar -xzf /tmp/azcopy.tar.gz -C /tmp && \
    mv /tmp/azcopy_linux_amd64_*/azcopy /usr/local/bin/azcopy && \
    chmod +x /usr/local/bin/azcopy && \
    rm -rf /tmp/azcopy* || true
```

The `|| true` prevents build failure if the download URL is unavailable; the tool degrades gracefully in `execute()` via `FileNotFoundError` handling.

- [ ] **Step 4: Add cloud-enum to the pip install**

Find the pip install line in the runtime stage (the one that installs `lib_webbh`) and add a separate `RUN pip install` after the source copy:

```dockerfile
RUN pip install --no-cache-dir cloud-enum aiohttp
```

Add this line after the `cp -a /app/shared/lib_webbh ...` line that installs `lib_webbh`.

- [ ] **Step 5: Verify the Dockerfile parses (syntax check)**

```
docker build --no-cache --target go-builder -f docker/Dockerfile.config_mgmt . -t conf11-gotest 2>&1 | tail -5
```

Expected: build completes the `go-builder` stage without error. If `s3scanner` fails to install, check the module path at `github.com/sa7mon/s3scanner@latest`.

- [ ] **Step 6: Commit**

```
git add docker/Dockerfile.config_mgmt
git commit -m "feat(conf11): add s3scanner, azcopy, and cloud-enum to config_mgmt image"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by task |
|---|---|
| Rewrite `CloudStorageAuditor` with `execute()` override | Task 6 |
| `build_command`/`parse_output` raise `NotImplementedError` | Task 1 (class skeleton) |
| Phase 1: DB asset query + live crawl | Task 6 (`_ingest` + `asyncio.gather`) |
| Phase 2: cloud_enum enumeration | Task 6 |
| Phase 3: s3scanner S3 scan | Tasks 2 + 6 |
| Phase 4: azcopy + aiohttp Azure scan | Tasks 4 + 6 |
| Phase 4: `(account, None)` container expansion via XML API | Task 6 |
| Phase 5: aiohttp GCS scan | Tasks 5 + 6 |
| Write probe PUT + DELETE cleanup | Task 6 |
| All severity mappings per spec | Tasks 2, 4, 5 |
| `section_id = "WSTG-CONF-11"` on all vulns | Tasks 2, 4, 5 |
| Deduplication by (location, name) | Task 6 |
| `job_state` update | Task 6 |
| `FileNotFoundError` per binary → skip phase | Task 6 |
| `asyncio.TimeoutError` per subprocess → skip phase | Task 6 |
| Temp file cleanup in `finally` blocks | Task 6 |
| `_SECTION_ID` constant | Task 1 |
| All 12 pure helper functions | Tasks 1–5 |
| All unit tests per spec | Tasks 1–5 |
| s3scanner in Dockerfile | Task 7 |
| azcopy in Dockerfile | Task 7 |
| cloud-enum pip install | Task 7 |

All spec sections covered. No gaps found.
