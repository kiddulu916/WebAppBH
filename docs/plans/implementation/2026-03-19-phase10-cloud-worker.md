# Phase 10 — Cloud Testing Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Dockerized cloud testing worker that discovers and probes public cloud resources (S3/Azure/GCP), scans for sensitive files and leaked secrets, and feeds findings back to the system.

**Architecture:** Single Docker container with 4-stage pipeline (Discovery → Probing → Deep Scan → Feed-back). Uses CloudEnum for OSINT, custom BucketProber with cloud SDKs for permission checks, TruffleHog for secret scanning. Reads from `cloud_queue`, writes to `cloud_assets`/`vulnerabilities`/`alerts` tables.

**Tech Stack:** Python 3.11, asyncio, boto3, azure-storage-blob, google-cloud-storage, SQLAlchemy (asyncpg), CloudEnum, TruffleHog

**Design doc:** `docs/plans/design/2026-03-19-phase10-cloud-worker-design.md`

---

### Task 1: Scaffold — `__init__.py`, `concurrency.py`

**Files:**
- Create: `workers/cloud_worker/__init__.py`
- Create: `workers/cloud_worker/concurrency.py`
- Test: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

```python
# tests/test_cloud_worker_tools.py
"""Tests for cloud_worker tools."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_cloud_worker_concurrency_weight_classes():
    from workers.cloud_worker.concurrency import WeightClass

    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


def test_cloud_worker_concurrency_get_semaphore():
    from workers.cloud_worker.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.HEAVY)
    assert sem is not None
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py::test_cloud_worker_concurrency_weight_classes -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'workers.cloud_worker'`

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/__init__.py
```

```python
# workers/cloud_worker/concurrency.py
"""Semaphore pools for heavy and light cloud-worker tools."""

import asyncio
import os
from enum import Enum

_heavy: asyncio.BoundedSemaphore | None = None
_light: asyncio.BoundedSemaphore | None = None


class WeightClass(Enum):
    HEAVY = "heavy"
    LIGHT = "light"


def get_semaphores(
    force_new: bool = False,
) -> tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
    """Return (heavy, light) semaphore pair.

    Reads HEAVY_CONCURRENCY and LIGHT_CONCURRENCY from env.
    Defaults: heavy=2, light=cpu_count().
    """
    global _heavy, _light
    if _heavy is None or _light is None or force_new:
        heavy_cap = int(os.environ.get("HEAVY_CONCURRENCY", "2"))
        light_cap = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))
        _heavy = asyncio.BoundedSemaphore(heavy_cap)
        _light = asyncio.BoundedSemaphore(light_cap)
    return _heavy, _light


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    """Return the semaphore for the given weight class."""
    heavy, light = get_semaphores()
    return heavy if weight is WeightClass.HEAVY else light
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_cloud_worker_tools.py -k "concurrency" -v`
Expected: 2 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/__init__.py workers/cloud_worker/concurrency.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): scaffold package with concurrency module"
```

---

### Task 2: Base Tool — `CloudTestTool(ABC)`

**Files:**
- Create: `workers/cloud_worker/base_tool.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
def test_cloud_test_tool_is_abstract():
    import inspect
    from workers.cloud_worker.base_tool import CloudTestTool

    assert inspect.isabstract(CloudTestTool)


def test_cloud_test_tool_provider_detection():
    from workers.cloud_worker.base_tool import detect_provider

    assert detect_provider("https://mybucket.s3.amazonaws.com") == "aws"
    assert detect_provider("https://myaccount.blob.core.windows.net/container") == "azure"
    assert detect_provider("https://storage.googleapis.com/mybucket") == "gcp"
    assert detect_provider("https://myapp.appspot.com") == "gcp"
    assert detect_provider("https://myapp.firebaseio.com") == "gcp"
    assert detect_provider("https://example.com") is None


CLOUD_URL_PATTERNS_FOR_TEST = [
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "appspot.com",
    "firebaseio.com",
]


def test_cloud_url_patterns_exported():
    from workers.cloud_worker.base_tool import CLOUD_URL_PATTERNS

    for pattern in CLOUD_URL_PATTERNS_FOR_TEST:
        assert any(pattern in p for p in CLOUD_URL_PATTERNS)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "cloud_test_tool" -v`
Expected: FAIL — `ModuleNotFoundError` or `ImportError`

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/base_tool.py
"""Abstract base class for cloud testing tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta

from sqlalchemy import select

from lib_webbh import (
    Alert,
    Asset,
    CloudAsset,
    JobState,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.concurrency import WeightClass

logger = setup_logger("cloud-test-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# ---------------------------------------------------------------------------
# Cloud URL patterns for detecting provider from URLs
# ---------------------------------------------------------------------------

CLOUD_URL_PATTERNS: list[str] = [
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "appspot.com",
    "firebaseio.com",
]

_PROVIDER_MAP: list[tuple[str, str]] = [
    ("s3.amazonaws.com", "aws"),
    ("blob.core.windows.net", "azure"),
    ("storage.googleapis.com", "gcp"),
    ("appspot.com", "gcp"),
    ("firebaseio.com", "gcp"),
]


def detect_provider(url: str) -> str | None:
    """Detect cloud provider from a URL. Returns 'aws', 'azure', 'gcp', or None."""
    lower = url.lower()
    for pattern, provider in _PROVIDER_MAP:
        if pattern in lower:
            return provider
    return None


class CloudTestTool(ABC):
    """Base class for all cloud testing tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class
    attributes and implement ``execute()``.
    """

    name: str
    weight_class: WeightClass

    # ------------------------------------------------------------------
    # Abstract method
    # ------------------------------------------------------------------

    @abstractmethod
    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        """Run the tool against *target* and return a stats dict."""

    # ------------------------------------------------------------------
    # Subprocess runner
    # ------------------------------------------------------------------

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        """Run a command and return decoded stdout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise

        return stdout_bytes.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Cooldown helpers
    # ------------------------------------------------------------------

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        """Return True if this tool was completed within COOLDOWN_HOURS."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=COOLDOWN_HOURS)
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
                JobState.status == "COMPLETED",
                JobState.last_tool_executed == self.name,
                JobState.last_seen >= cutoff,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None

    async def update_tool_state(self, target_id: int, container_name: str) -> None:
        """Update JobState.last_tool_executed and last_seen for this tool."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.last_tool_executed = self.name
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    # ------------------------------------------------------------------
    # Cloud asset query helpers
    # ------------------------------------------------------------------

    async def _get_cloud_assets(self, target_id: int) -> list[CloudAsset]:
        """Fetch all CloudAsset rows for a target."""
        async with get_session() as session:
            stmt = select(CloudAsset).where(CloudAsset.target_id == target_id)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_public_cloud_assets(self, target_id: int) -> list[CloudAsset]:
        """Fetch CloudAsset rows where is_public=True for a target."""
        async with get_session() as session:
            stmt = select(CloudAsset).where(
                CloudAsset.target_id == target_id,
                CloudAsset.is_public.is_(True),
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_cloud_urls_from_assets(
        self, target_id: int
    ) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets matching cloud URL patterns."""
        from sqlalchemy import or_

        async with get_session() as session:
            conditions = [
                Asset.asset_value.ilike(f"%{pattern}%")
                for pattern in CLOUD_URL_PATTERNS
            ]
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                or_(*conditions),
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    async def _save_cloud_asset(
        self,
        target_id: int,
        provider: str,
        asset_type: str,
        url: str,
        is_public: bool = False,
        findings: dict | None = None,
    ) -> int:
        """Upsert a CloudAsset row. Returns the cloud asset id."""
        async with get_session() as session:
            stmt = select(CloudAsset).where(
                CloudAsset.target_id == target_id,
                CloudAsset.url == url,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                existing.is_public = is_public
                if findings is not None:
                    existing.findings = findings
                await session.commit()
                return existing.id

            ca = CloudAsset(
                target_id=target_id,
                provider=provider,
                asset_type=asset_type,
                url=url,
                is_public=is_public,
                findings=findings,
            )
            session.add(ca)
            await session.flush()
            ca_id = ca.id
            await session.commit()
            return ca_id

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _save_asset(
        self,
        target_id: int,
        url: str,
        scope_manager: ScopeManager,
        source_tool: str | None = None,
    ) -> int | None:
        """Scope-check and upsert an Asset row. Returns asset id or None."""
        scope_result = scope_manager.is_in_scope(url)
        if not scope_result.in_scope:
            return None

        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type == scope_result.asset_type,
                Asset.asset_value == scope_result.normalized,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing is not None:
                return existing.id

            asset = Asset(
                target_id=target_id,
                asset_type=scope_result.asset_type,
                asset_value=scope_result.normalized,
                source_tool=source_tool or self.name,
            )
            session.add(asset)
            await session.commit()
            return asset.id

    async def _save_vulnerability(
        self,
        target_id: int,
        asset_id: int | None,
        severity: str,
        title: str,
        description: str,
        poc: str | None = None,
    ) -> int:
        """Insert a Vulnerability row and create an Alert for critical/high."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity=severity,
                title=title,
                description=description,
                poc=poc,
                source_tool=self.name,
            )
            session.add(vuln)
            await session.flush()
            vuln_id = vuln.id
            await session.commit()

        if severity in ("critical", "high"):
            await self._create_alert(
                target_id,
                vuln_id,
                f"[{severity.upper()}] {title}",
            )

        return vuln_id

    # ------------------------------------------------------------------
    # Alerting
    # ------------------------------------------------------------------

    async def _create_alert(
        self,
        target_id: int,
        vuln_id: int,
        message: str,
    ) -> None:
        """Write alert to DB and push to Redis for SSE."""
        logger.warning(f"ALERT: {message}")
        async with get_session() as session:
            alert = Alert(
                target_id=target_id,
                vulnerability_id=vuln_id,
                alert_type="critical",
                message=message,
            )
            session.add(alert)
            await session.commit()
            alert_id = alert.id

        await push_task(f"events:{target_id}", {
            "event": "critical_alert",
            "alert_id": alert_id,
            "vulnerability_id": vuln_id,
            "message": message,
        })
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "cloud_test_tool or cloud_url_patterns" -v`
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/base_tool.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add CloudTestTool base class with cloud helpers"
```

---

### Task 3: Stage 1 Tool — `asset_scraper.py`

**Files:**
- Create: `workers/cloud_worker/tools/__init__.py`
- Create: `workers/cloud_worker/tools/asset_scraper.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
# ===================================================================
# AssetScraperTool tests
# ===================================================================

def test_asset_scraper_classify_url():
    from workers.cloud_worker.tools.asset_scraper import AssetScraperTool

    tool = AssetScraperTool()
    assert tool.classify_url("https://mybucket.s3.amazonaws.com") == ("aws", "s3_bucket")
    assert tool.classify_url("https://myaccount.blob.core.windows.net/container") == ("azure", "blob_container")
    assert tool.classify_url("https://storage.googleapis.com/mybucket") == ("gcp", "gcs_bucket")
    assert tool.classify_url("https://myapp.firebaseio.com") == ("gcp", "firebase_db")
    assert tool.classify_url("https://myapp.appspot.com") == ("gcp", "appspot")
    assert tool.classify_url("https://example.com") is None


def test_asset_scraper_dedup_urls():
    from workers.cloud_worker.tools.asset_scraper import AssetScraperTool

    tool = AssetScraperTool()
    urls = [
        "https://mybucket.s3.amazonaws.com",
        "https://mybucket.s3.amazonaws.com",  # duplicate
        "https://other.s3.amazonaws.com",
    ]
    deduped = tool.deduplicate(urls)
    assert len(deduped) == 2
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "asset_scraper" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/tools/__init__.py
from workers.cloud_worker.tools.asset_scraper import AssetScraperTool

__all__ = [
    "AssetScraperTool",
]
```

```python
# workers/cloud_worker/tools/asset_scraper.py
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
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "asset_scraper" -v`
Expected: 2 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/tools/__init__.py workers/cloud_worker/tools/asset_scraper.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add AssetScraperTool for dual-source cloud URL discovery"
```

---

### Task 4: Stage 1 Tool — `cloud_enum.py`

**Files:**
- Create: `workers/cloud_worker/tools/cloud_enum.py`
- Modify: `workers/cloud_worker/tools/__init__.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
# ===================================================================
# CloudEnumTool tests
# ===================================================================

SAMPLE_CLOUD_ENUM_OUTPUT = """
[+] Checking for S3 Buckets
[+] Found open S3 bucket: acme-backup.s3.amazonaws.com
[+] Found open S3 bucket: acme-assets.s3.amazonaws.com
[+] Checking for Azure Blobs
[+] Found open Azure container: acme.blob.core.windows.net/public
[+] Checking for GCP Buckets
[+] Found open GCP bucket: storage.googleapis.com/acme-data
"""


def test_cloud_enum_parse_output():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    results = tool.parse_output(SAMPLE_CLOUD_ENUM_OUTPUT)
    assert len(results) == 4
    assert any("acme-backup.s3.amazonaws.com" in r for r in results)
    assert any("blob.core.windows.net" in r for r in results)
    assert any("storage.googleapis.com" in r for r in results)


def test_cloud_enum_parse_output_empty():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    results = tool.parse_output("")
    assert results == []


def test_cloud_enum_build_command():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    cmd = tool.build_command("acme.com", mutations=["corp", "dev"])
    assert "cloud_enum" in cmd[0] or "cloud_enum" in " ".join(cmd)
    assert "-k" in cmd
    assert "acme.com" in cmd


from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.anyio
async def test_cloud_enum_skips_on_cooldown():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "cloud_enum" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
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

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> list[str]:
        """Extract cloud resource URLs from cloud_enum stdout."""
        if not raw.strip():
            return []
        matches = _URL_RE.findall(raw)
        # Deduplicate preserving order
        seen: set[str] = set()
        results: list[str] = []
        for m in matches:
            if m.lower() not in seen:
                seen.add(m.lower())
                results.append(m)
        return results

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
            log.info("Skipping cloud_enum -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        keyword = profile.get("primary_domain", "")
        if not keyword:
            # Fallback: extract from target name
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

            # Ensure URL has scheme for DB storage
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
```

Update `workers/cloud_worker/tools/__init__.py`:

```python
from workers.cloud_worker.tools.asset_scraper import AssetScraperTool
from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

__all__ = [
    "AssetScraperTool",
    "CloudEnumTool",
]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "cloud_enum" -v`
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/tools/cloud_enum.py workers/cloud_worker/tools/__init__.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add CloudEnumTool for multi-cloud OSINT discovery"
```

---

### Task 5: Stage 2 Tool — `bucket_prober.py`

**Files:**
- Create: `workers/cloud_worker/tools/bucket_prober.py`
- Modify: `workers/cloud_worker/tools/__init__.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
# ===================================================================
# BucketProberTool tests
# ===================================================================

def test_bucket_prober_extract_s3_bucket_name():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    assert tool.extract_bucket_name("https://mybucket.s3.amazonaws.com", "aws") == "mybucket"
    assert tool.extract_bucket_name("https://s3.amazonaws.com/mybucket", "aws") == "mybucket"
    assert tool.extract_bucket_name("https://mybucket.s3.us-west-2.amazonaws.com", "aws") == "mybucket"


def test_bucket_prober_extract_azure_container():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    name = tool.extract_bucket_name(
        "https://myaccount.blob.core.windows.net/mycontainer", "azure"
    )
    assert name == "mycontainer"


def test_bucket_prober_extract_gcs_bucket_name():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    assert tool.extract_bucket_name("https://storage.googleapis.com/mybucket", "gcp") == "mybucket"


def test_bucket_prober_severity_for_permissions():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    assert tool.severity_for_access("write") == "critical"
    assert tool.severity_for_access("read") == "high"
    assert tool.severity_for_access("list") == "high"
    assert tool.severity_for_access("none") == "info"


@pytest.mark.anyio
async def test_bucket_prober_skips_on_cooldown():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "bucket_prober" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/tools/bucket_prober.py
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def extract_bucket_name(self, url: str, provider: str) -> str:
        """Extract bucket/container name from a cloud URL."""
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")

        if provider == "aws":
            host = parsed.hostname or ""
            # Virtual-hosted style: mybucket.s3.amazonaws.com
            if host.endswith(".amazonaws.com") and host != "s3.amazonaws.com":
                return host.split(".s3")[0]
            # Path style: s3.amazonaws.com/mybucket
            path_parts = parsed.path.strip("/").split("/")
            return path_parts[0] if path_parts else ""

        if provider == "azure":
            # myaccount.blob.core.windows.net/container
            path_parts = parsed.path.strip("/").split("/")
            return path_parts[0] if path_parts else ""

        if provider == "gcp":
            # storage.googleapis.com/mybucket
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

    # ------------------------------------------------------------------
    # Provider-specific probers
    # ------------------------------------------------------------------

    async def _probe_s3(self, bucket_name: str) -> dict:
        """Probe an S3 bucket for public access using anonymous boto3 client."""
        import botocore.session
        from botocore import UNSIGNED
        from botocore.config import Config

        findings: dict = {"readable": False, "writable": False, "acl_public": False, "details": {}}
        session = botocore.session.get_session()
        client = session.create_client(
            "s3", config=Config(signature_version=UNSIGNED)
        )

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
            client = ContainerClient(
                account_url=account_url,
                container_name=container_name,
            )
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

            # Scope check
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

            # Update cloud_asset
            await self._save_cloud_asset(
                target_id=target_id,
                provider=ca.provider,
                asset_type=ca.asset_type,
                url=ca.url,
                is_public=is_public,
                findings=findings,
            )

            # Create vulnerability if public
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
```

Update `workers/cloud_worker/tools/__init__.py`:

```python
from workers.cloud_worker.tools.asset_scraper import AssetScraperTool
from workers.cloud_worker.tools.cloud_enum import CloudEnumTool
from workers.cloud_worker.tools.bucket_prober import BucketProberTool

__all__ = [
    "AssetScraperTool",
    "CloudEnumTool",
    "BucketProberTool",
]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "bucket_prober" -v`
Expected: 5 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/tools/bucket_prober.py workers/cloud_worker/tools/__init__.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add BucketProberTool with AWS/Azure/GCP permission probing"
```

---

### Task 6: Stage 3 Tool — `file_lister.py`

**Files:**
- Create: `workers/cloud_worker/tools/file_lister.py`
- Modify: `workers/cloud_worker/tools/__init__.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
# ===================================================================
# FileListerTool tests
# ===================================================================

def test_file_lister_sensitive_patterns():
    from workers.cloud_worker.tools.file_lister import FileListerTool

    tool = FileListerTool()
    assert tool.is_sensitive("backup.sql") is True
    assert tool.is_sensitive(".env") is True
    assert tool.is_sensitive("id_rsa.pem") is True
    assert tool.is_sensitive("credentials.json") is True
    assert tool.is_sensitive("server.key") is True
    assert tool.is_sensitive(".htpasswd") is True
    assert tool.is_sensitive("db_dump.bak") is True
    assert tool.is_sensitive("index.html") is False
    assert tool.is_sensitive("logo.png") is False


def test_file_lister_severity_for_file():
    from workers.cloud_worker.tools.file_lister import FileListerTool

    tool = FileListerTool()
    assert tool.severity_for_file("private.pem") == "critical"
    assert tool.severity_for_file("server.key") == "critical"
    assert tool.severity_for_file("id_rsa") == "critical"
    assert tool.severity_for_file(".env") == "high"
    assert tool.severity_for_file("credentials.json") == "high"
    assert tool.severity_for_file("dump.sql") == "high"
    assert tool.severity_for_file("config.yml") == "medium"
    assert tool.severity_for_file("export.csv") == "medium"


@pytest.mark.anyio
async def test_file_lister_skips_on_cooldown():
    from workers.cloud_worker.tools.file_lister import FileListerTool

    tool = FileListerTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "file_lister" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
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

# Severity tiers for sensitive file patterns
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Provider-specific listers
    # ------------------------------------------------------------------

    async def _list_s3(self, bucket_name: str) -> list[str]:
        """List up to MAX_OBJECTS keys in an S3 bucket."""
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
        """List up to MAX_OBJECTS blobs in an Azure container."""
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
        """List up to MAX_OBJECTS objects in a GCP bucket."""
        from google.cloud import storage as gcs
        from google.auth.credentials import AnonymousCredentials

        client = gcs.Client(credentials=AnonymousCredentials(), project="none")
        bucket = client.bucket(bucket_name)
        return [blob.name for blob in bucket.list_blobs(max_results=MAX_OBJECTS)]

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

            # Update findings with sensitive files list
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
```

Update `workers/cloud_worker/tools/__init__.py`:

```python
from workers.cloud_worker.tools.asset_scraper import AssetScraperTool
from workers.cloud_worker.tools.cloud_enum import CloudEnumTool
from workers.cloud_worker.tools.bucket_prober import BucketProberTool
from workers.cloud_worker.tools.file_lister import FileListerTool

__all__ = [
    "AssetScraperTool",
    "CloudEnumTool",
    "BucketProberTool",
    "FileListerTool",
]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "file_lister" -v`
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/tools/file_lister.py workers/cloud_worker/tools/__init__.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add FileListerTool for sensitive filename detection"
```

---

### Task 7: Stage 3 Tool — `trufflehog_cloud.py`

**Files:**
- Create: `workers/cloud_worker/tools/trufflehog_cloud.py`
- Modify: `workers/cloud_worker/tools/__init__.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
# ===================================================================
# TrufflehogCloudTool tests
# ===================================================================

import json as _json

SAMPLE_TRUFFLEHOG_CLOUD_OUTPUT = "\n".join([
    _json.dumps({
        "SourceMetadata": {
            "Data": {"S3": {"bucket": "acme-backup", "file": "config/.env"}}
        },
        "DetectorName": "AWS",
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "Verified": True,
    }),
    _json.dumps({
        "SourceMetadata": {
            "Data": {"S3": {"bucket": "acme-backup", "file": "dump.sql"}}
        },
        "DetectorName": "Generic",
        "Raw": "sk_live_abc123def456",
        "Verified": False,
    }),
])


def test_trufflehog_cloud_parse_output():
    from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

    tool = TrufflehogCloudTool()
    findings = tool.parse_output(SAMPLE_TRUFFLEHOG_CLOUD_OUTPUT)
    assert len(findings) == 2
    assert findings[0]["detector"] == "AWS"
    assert findings[0]["verified"] is True
    assert findings[1]["detector"] == "Generic"
    assert findings[1]["verified"] is False


def test_trufflehog_cloud_parse_output_empty():
    from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

    tool = TrufflehogCloudTool()
    findings = tool.parse_output("")
    assert findings == []


def test_trufflehog_cloud_build_s3_command():
    from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

    tool = TrufflehogCloudTool()
    cmd = tool.build_command("acme-backup", "aws")
    assert "trufflehog" in cmd
    assert "s3" in cmd
    assert "--bucket=acme-backup" in cmd


def test_trufflehog_cloud_build_gcs_command():
    from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

    tool = TrufflehogCloudTool()
    cmd = tool.build_command("acme-data", "gcp")
    assert "gcs" in cmd


def test_trufflehog_cloud_is_credential_type():
    from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

    tool = TrufflehogCloudTool()
    assert tool.is_credential_type("AWS") is True
    assert tool.is_credential_type("Azure") is True
    assert tool.is_credential_type("GCP") is True
    assert tool.is_credential_type("PrivateKey") is True
    assert tool.is_credential_type("Generic") is False


@pytest.mark.anyio
async def test_trufflehog_cloud_skips_on_cooldown():
    from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

    tool = TrufflehogCloudTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "trufflehog_cloud" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/tools/trufflehog_cloud.py
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

# Detector names that indicate cloud credentials
_CREDENTIAL_DETECTORS = {"aws", "azure", "gcp", "privatekey", "googlecloud"}


class TrufflehogCloudTool(CloudTestTool):
    """Scan public cloud buckets for leaked secrets with TruffleHog."""

    name = "trufflehog_cloud"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

    def build_command(self, bucket_name: str, provider: str) -> list[str]:
        """Build the trufflehog CLI command for cloud scanning."""
        if provider == "aws":
            return [
                "trufflehog", "s3",
                f"--bucket={bucket_name}",
                "--json",
                "--no-update",
            ]
        if provider == "gcp":
            return [
                "trufflehog", "gcs",
                f"--bucket={bucket_name}",
                "--json",
                "--no-update",
            ]
        # Azure: fall back to filesystem scan (no native support)
        return [
            "trufflehog", "filesystem",
            "/dev/null",  # placeholder — Azure handled separately
            "--json",
            "--no-update",
        ]

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> list[dict]:
        """Parse trufflehog JSON-lines output."""
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
                # Check S3, GCS, or Filesystem source metadata
                for source_key in ("S3", "GCS", "Filesystem"):
                    if source_key in source_meta:
                        src = source_meta[source_key]
                        finding["source"] = src.get("file", src.get("bucket", ""))
                        break
                findings.append(finding)
            except json.JSONDecodeError:
                continue
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_credential_type(detector: str) -> bool:
        """Return True if the detector indicates cloud credentials."""
        return detector.lower() in _CREDENTIAL_DETECTORS

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

            # Skip Azure — no native trufflehog support
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

                # Mask the raw secret
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
```

Update `workers/cloud_worker/tools/__init__.py`:

```python
from workers.cloud_worker.tools.asset_scraper import AssetScraperTool
from workers.cloud_worker.tools.cloud_enum import CloudEnumTool
from workers.cloud_worker.tools.bucket_prober import BucketProberTool
from workers.cloud_worker.tools.file_lister import FileListerTool
from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool

__all__ = [
    "AssetScraperTool",
    "CloudEnumTool",
    "BucketProberTool",
    "FileListerTool",
    "TrufflehogCloudTool",
]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "trufflehog_cloud" -v`
Expected: 6 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/tools/trufflehog_cloud.py workers/cloud_worker/tools/__init__.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add TrufflehogCloudTool for native bucket secret scanning"
```

---

### Task 8: Stage 4 Tool — `cloud_feedbacker.py`

**Files:**
- Create: `workers/cloud_worker/tools/cloud_feedbacker.py`
- Modify: `workers/cloud_worker/tools/__init__.py`
- Modify: `tests/test_cloud_worker_tools.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_tools.py`:

```python
# ===================================================================
# CloudFeedbackerTool tests
# ===================================================================

def test_feedbacker_extract_domains_from_urls():
    from workers.cloud_worker.tools.cloud_feedbacker import CloudFeedbackerTool

    tool = CloudFeedbackerTool()
    urls = [
        "https://acme-backup.s3.amazonaws.com",
        "https://myaccount.blob.core.windows.net/container",
        "https://storage.googleapis.com/acme-data",
    ]
    domains = tool.extract_domains(urls)
    assert "acme-backup.s3.amazonaws.com" in domains
    assert "myaccount.blob.core.windows.net" in domains
    assert "storage.googleapis.com" in domains


def test_feedbacker_is_credential_vuln():
    from workers.cloud_worker.tools.cloud_feedbacker import CloudFeedbackerTool

    tool = CloudFeedbackerTool()
    assert tool.is_credential_vuln("Verified secret (AWS) in AWS bucket") is True
    assert tool.is_credential_vuln("Verified secret (Azure) in AZURE bucket") is True
    assert tool.is_credential_vuln("Public S3 bucket: read access") is False


@pytest.mark.anyio
async def test_feedbacker_skips_on_cooldown():
    from workers.cloud_worker.tools.cloud_feedbacker import CloudFeedbackerTool

    tool = CloudFeedbackerTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_tools.py -k "feedbacker" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_domains(urls: list[str]) -> list[str]:
        """Extract unique hostnames from a list of URLs."""
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
        """Return True if vulnerability title indicates cloud credential leak."""
        lower = title.lower()
        return any(kw in lower for kw in _CREDENTIAL_KEYWORDS) and "secret" in lower

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
            log.info("Skipping cloud_feedbacker -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Collect all cloud asset URLs
        cloud_assets = await self._get_cloud_assets(target_id)
        urls = [ca.url for ca in cloud_assets if ca.url]
        domains = self.extract_domains(urls)
        stats["found"] = len(domains)

        # Push in-scope domains to recon_queue
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

        # Check for credential-type vulnerabilities and generate alerts
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
                    "event": "cloud_credential_leak",
                    "vulnerability_id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "message": f"Cloud credential leaked: {vuln.title}",
                })

        await self.update_tool_state(target_id, container_name)
        log.info("cloud_feedbacker complete", extra=stats)
        return stats
```

Update `workers/cloud_worker/tools/__init__.py`:

```python
from workers.cloud_worker.tools.asset_scraper import AssetScraperTool
from workers.cloud_worker.tools.cloud_enum import CloudEnumTool
from workers.cloud_worker.tools.bucket_prober import BucketProberTool
from workers.cloud_worker.tools.file_lister import FileListerTool
from workers.cloud_worker.tools.trufflehog_cloud import TrufflehogCloudTool
from workers.cloud_worker.tools.cloud_feedbacker import CloudFeedbackerTool

__all__ = [
    "AssetScraperTool",
    "CloudEnumTool",
    "BucketProberTool",
    "FileListerTool",
    "TrufflehogCloudTool",
    "CloudFeedbackerTool",
]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_tools.py -k "feedbacker" -v`
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/tools/cloud_feedbacker.py workers/cloud_worker/tools/__init__.py tests/test_cloud_worker_tools.py
git commit -m "feat(cloud-worker): add CloudFeedbackerTool for recon feed-back and credential alerts"
```

---

### Task 9: Pipeline — `pipeline.py`

**Files:**
- Create: `workers/cloud_worker/pipeline.py`
- Create: `tests/test_cloud_worker_pipeline.py`

**Step 1: Write the failing test**

```python
# tests/test_cloud_worker_pipeline.py
"""Tests for cloud_worker pipeline."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_pipeline_has_four_stages():
    from workers.cloud_worker.pipeline import STAGES

    assert len(STAGES) == 4


def test_pipeline_stage_names():
    from workers.cloud_worker.pipeline import STAGES

    names = [s.name for s in STAGES]
    assert names == ["discovery", "probing", "deep_scan", "feedback"]


def test_pipeline_stage_index():
    from workers.cloud_worker.pipeline import STAGE_INDEX

    assert STAGE_INDEX["discovery"] == 0
    assert STAGE_INDEX["probing"] == 1
    assert STAGE_INDEX["deep_scan"] == 2
    assert STAGE_INDEX["feedback"] == 3


def test_pipeline_aggregate_results():
    from workers.cloud_worker.pipeline import Pipeline

    p = Pipeline(target_id=1, container_name="test")
    results = [
        {"found": 5, "in_scope": 3, "new": 2},
        {"found": 10, "in_scope": 8, "new": 6},
        ValueError("tool failed"),
    ]
    agg = p._aggregate_results("test_stage", results)
    assert agg["found"] == 15
    assert agg["in_scope"] == 11
    assert agg["new"] == 8
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_pipeline.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/pipeline.py
"""Cloud testing pipeline: 4 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.base_tool import CloudTestTool
from workers.cloud_worker.tools import (
    AssetScraperTool,
    CloudEnumTool,
    BucketProberTool,
    FileListerTool,
    TrufflehogCloudTool,
    CloudFeedbackerTool,
)

logger = setup_logger("cloud-pipeline")

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------


@dataclass
class Stage:
    name: str
    tool_classes: list[type[CloudTestTool]]


STAGES: list[Stage] = [
    Stage("discovery", [CloudEnumTool, AssetScraperTool]),
    Stage("probing", [BucketProberTool]),
    Stage("deep_scan", [FileListerTool, TrufflehogCloudTool]),
    Stage("feedback", [CloudFeedbackerTool]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


_rebuild_index()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Orchestrates the 4-stage cloud testing pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str) -> None:
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        target,
        scope_manager: ScopeManager,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        _rebuild_index()

        completed_phase = await self._get_completed_phase()
        start_index = 0

        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        for stage in STAGES[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            stats = await self._run_stage(stage, target, scope_manager)

            self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
            await push_task(f"events:{self.target_id}", {
                "event": "stage_complete",
                "stage": stage.name,
                "stats": stats,
            })

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "pipeline_complete",
            "target_id": self.target_id,
        })

    # ------------------------------------------------------------------
    # Stage runners
    # ------------------------------------------------------------------

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        **kwargs,
    ) -> dict:
        """Run all tools in a stage concurrently."""
        tools = [cls() for cls in stage.tool_classes]

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                **kwargs,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._aggregate_results(stage.name, results)

    # ------------------------------------------------------------------
    # Checkpoint helpers
    # ------------------------------------------------------------------

    async def _get_completed_phase(self) -> str | None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
                JobState.status == "COMPLETED",
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            return job.current_phase if job else None

    async def _update_phase(self, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.current_phase = phase
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_stats(aggregated: dict, result: dict) -> None:
        aggregated["found"] += result.get("found", 0)
        aggregated["in_scope"] += result.get("in_scope", 0)
        aggregated["new"] += result.get("new", 0)

    def _aggregate_results(self, stage_name: str, results: list) -> dict:
        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(
                    f"Tool failed in {stage_name}", extra={"error": str(r)}
                )
                continue
            self._merge_stats(aggregated, r)
        return aggregated
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_pipeline.py -v`
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/pipeline.py tests/test_cloud_worker_pipeline.py
git commit -m "feat(cloud-worker): add 4-stage cloud testing pipeline with checkpointing"
```

---

### Task 10: Entry Point — `main.py`

**Files:**
- Create: `workers/cloud_worker/main.py`
- Modify: `tests/test_cloud_worker_pipeline.py`

**Step 1: Write the failing test**

Append to `tests/test_cloud_worker_pipeline.py`:

```python
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.anyio
async def test_handle_message_missing_target_id():
    from workers.cloud_worker.main import handle_message

    # Should return without error when target_id is missing
    await handle_message("msg-1", {})


@pytest.mark.anyio
async def test_handle_message_target_not_found():
    from workers.cloud_worker.main import handle_message

    with patch("workers.cloud_worker.main.get_session") as mock_gs:
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        mock_gs.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_gs.return_value.__aexit__ = AsyncMock(return_value=False)

        # Should return without error when target not found
        await handle_message("msg-2", {"target_id": 999})
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cloud_worker_pipeline.py -k "handle_message" -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/cloud_worker/main.py
"""Cloud testing worker entry point.

Listens on ``cloud_queue`` and runs the 4-stage
cloud testing pipeline for each incoming target.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_queue,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.pipeline import Pipeline

logger = setup_logger("cloud-worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "cloud-worker-unknown")


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single cloud_queue message."""
    target_id = data.get("target_id")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info("Received cloud testing task", extra={"msg_id": msg_id})

    # Load target
    async with get_session() as session:
        stmt = select(Target).where(Target.id == target_id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

    if target is None:
        log.error(f"Target {target_id} not found in database")
        return

    container_name = get_container_name()
    profile = target.target_profile or {}
    scope_manager = ScopeManager(profile)

    # Ensure job_state row
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if job is None:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                current_phase="init",
                status="RUNNING",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.now(timezone.utc)
        await session.commit()

    # Run pipeline with heartbeat
    pipeline = Pipeline(target_id=target_id, container_name=container_name)
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(target_id, container_name)
    )

    try:
        await pipeline.run(target, scope_manager)
    except Exception:
        log.exception("Pipeline failed")
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "FAILED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    """Update job_state.last_seen every HEARTBEAT_INTERVAL seconds."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass


async def main() -> None:
    """Entry point: listen on cloud_queue forever."""
    container_name = get_container_name()
    logger.info("Cloud testing worker starting", extra={"container": container_name})

    await listen_queue(
        queue="cloud_queue",
        group="cloud_group",
        consumer=container_name,
        callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cloud_worker_pipeline.py -v`
Expected: 6 PASSED

**Step 5: Commit**

```bash
git add workers/cloud_worker/main.py tests/test_cloud_worker_pipeline.py
git commit -m "feat(cloud-worker): add main.py entry point with queue listener and heartbeat"
```

---

### Task 11: Dockerfile

**Files:**
- Create: `docker/Dockerfile.cloud`

**Step 1: Write the Dockerfile**

```dockerfile
# docker/Dockerfile.cloud
# -------------------------------------------------------
# Cloud Testing Worker
# -------------------------------------------------------

# Stage 1: Builder — install Go tools and Python packages
FROM webbh-base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git golang-go ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install cloud_enum
RUN pip install --no-cache-dir cloud_enum

# Install trufflehog binary
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Stage 2: Runtime
FROM webbh-base AS runtime

# Python cloud SDK dependencies
RUN pip install --no-cache-dir \
    boto3 \
    botocore \
    azure-storage-blob \
    google-cloud-storage \
    httpx

# Copy tools from builder
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/cloud_enum /usr/local/bin/cloud_enum

# Copy shared lib and worker code
COPY shared/ /app/shared/
RUN pip install -e /app/shared/lib_webbh

COPY workers/ /app/workers/

WORKDIR /app

ENTRYPOINT ["python", "-m", "workers.cloud_worker.main"]
```

**Step 2: Commit**

```bash
git add docker/Dockerfile.cloud
git commit -m "feat(cloud-worker): add Dockerfile.cloud with cloud SDKs and tools"
```

---

### Task 12: Run all tests

**Step 1: Run the full cloud worker test suite**

Run: `pytest tests/test_cloud_worker_tools.py tests/test_cloud_worker_pipeline.py -v`
Expected: All tests PASS

**Step 2: Run the full project test suite to check for regressions**

Run: `pytest -v`
Expected: No regressions — all existing tests still PASS

**Step 3: Final commit if any fixups needed**

```bash
git add -A
git commit -m "test(cloud-worker): all Phase 10 tests passing"
```
