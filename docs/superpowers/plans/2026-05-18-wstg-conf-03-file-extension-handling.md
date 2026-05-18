# WSTG-CONF-03: File Extension Handling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `FileExtensionTester` to fully implement WSTG-CONF-03 — DB-integrated path discovery, source code disclosure detection, credential pattern checking, and conditional Windows 8.3 bypass testing.

**Architecture:** `FileExtensionTester.execute()` is overridden entirely. It queries the DB for paths discovered in prior stages, builds a test matrix of path-stems × extension-categories, runs async `httpx` probes with an inner semaphore of 20, and persists findings via the base class `_process_vulnerability()` helper. `build_command()` and `parse_output()` are stubs that raise `NotImplementedError` — they are never called.

**Tech Stack:** Python 3.11+, `asyncio`, `httpx` (already in container via inline scripts), SQLAlchemy async (`lib_webbh.get_session`), `pytest` with `asyncio_mode = auto`, `unittest.mock`

---

## File Map

| Action | File | Responsibility |
|---|---|---|
| Modify | `workers/config_mgmt/tools/file_extension_tester.py` | Full rewrite — all logic here |
| Create | `tests/unit/__init__.py` | pytest package marker |
| Create | `tests/unit/workers/__init__.py` | pytest package marker |
| Create | `tests/unit/workers/config_mgmt/__init__.py` | pytest package marker |
| Create | `tests/unit/workers/config_mgmt/test_file_extension_tester.py` | All unit tests |

**No changes** to `pipeline.py`, `concurrency.py`, `tools/__init__.py`, `playbooks.py`, or the dashboard — the `file_extension_handling` stage slot and `FileExtensionTester` registration already exist.

---

## Task 1: Test infrastructure setup

**Files:**
- Create: `tests/unit/__init__.py`
- Create: `tests/unit/workers/__init__.py`
- Create: `tests/unit/workers/config_mgmt/__init__.py`

- [ ] **Step 1: Create package markers**

```bash
mkdir -p tests/unit/workers/config_mgmt
touch tests/unit/__init__.py
touch tests/unit/workers/__init__.py
touch tests/unit/workers/config_mgmt/__init__.py
```

- [ ] **Step 2: Confirm pytest can discover the directory**

```bash
pytest tests/unit/ -v --collect-only
```

Expected: `no tests ran` — the directory exists but has no test files yet. An error here means pytest can't find the directory; verify the `mkdir` ran from the repo root.

---

## Task 2: Pure functions — `_generate_short_name` and `_analyze_response`

**Files:**
- Create: `tests/unit/workers/config_mgmt/test_file_extension_tester.py`
- Modify: `workers/config_mgmt/tools/file_extension_tester.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/workers/config_mgmt/test_file_extension_tester.py` with this full content:

```python
"""Unit tests for WSTG-CONF-03 FileExtensionTester."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from workers.config_mgmt.tools.file_extension_tester import (
    FileExtensionTester,
    _generate_short_name,
)


# ── _generate_short_name ──────────────────────────────────────────────────────

def test_generate_short_name_standard():
    assert _generate_short_name("/webconfig") == "WEBCON"


def test_generate_short_name_short_path_returns_empty():
    assert _generate_short_name("/ab") == ""


def test_generate_short_name_root_returns_empty():
    assert _generate_short_name("/") == ""


def test_generate_short_name_strips_special_chars():
    # hyphens and dots are removed; only alphanumeric kept, then truncated to 6
    assert _generate_short_name("/my-config.php") == "MYCONF"


def test_generate_short_name_exact_six_chars():
    assert _generate_short_name("/backup") == "BACKUP"


# ── _analyze_response helpers ─────────────────────────────────────────────────

def _mock_resp(body: str, content_type: str = "text/html") -> MagicMock:
    resp = MagicMock()
    resp.text = body
    resp.headers = {"content-type": content_type}
    return resp


# ── _analyze_response ─────────────────────────────────────────────────────────

def test_analyze_response_database_is_critical():
    result = FileExtensionTester._analyze_response(
        "http://t/db.sql", "/db", ".sql", "database",
        _mock_resp("-- SQL dump")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-03"


def test_analyze_response_credentials_upgrade_to_critical():
    result = FileExtensionTester._analyze_response(
        "http://t/config.bak", "/config", ".bak", "backup",
        _mock_resp("password=hunter2")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_response_never_serve_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/app.asa", "/app", ".asa", "never_serve",
        _mock_resp("some content")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_source_code_with_php_syntax_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/index.php", "/index", ".php", "source_code",
        _mock_resp("<?php echo 'hello'; ?>")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_source_code_plain_text_content_type_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/index.php", "/index", ".php", "source_code",
        _mock_resp("some code", content_type="text/plain")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_source_code_html_no_syntax_is_none():
    # App is executing the PHP (returns HTML) — not a disclosure finding
    result = FileExtensionTester._analyze_response(
        "http://t/index.php", "/index", ".php", "source_code",
        _mock_resp("<html><body>Welcome</body></html>", content_type="text/html")
    )
    assert result is None


def test_analyze_response_document_no_creds_is_none():
    result = FileExtensionTester._analyze_response(
        "http://t/readme.txt", "/readme", ".txt", "document",
        _mock_resp("This is the readme file.")
    )
    assert result is None


def test_analyze_response_document_with_creds_is_critical():
    result = FileExtensionTester._analyze_response(
        "http://t/notes.txt", "/notes", ".txt", "document",
        _mock_resp("admin password=letmein")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_response_archive_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/backup.zip", "/backup", ".zip", "archive",
        _mock_resp("PK binary data")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_config_is_medium():
    result = FileExtensionTester._analyze_response(
        "http://t/app.yml", "/app", ".yml", "configuration",
        _mock_resp("app:\n  name: myapp")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "medium"
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/unit/workers/config_mgmt/test_file_extension_tester.py -v
```

Expected: `ImportError` or `AttributeError` — the current `file_extension_tester.py` has no `_generate_short_name` function and no `_analyze_response` method.

- [ ] **Step 3: Replace `file_extension_tester.py` with the new pure-function layer**

Replace the entire contents of `workers/config_mgmt/tools/file_extension_tester.py`:

```python
"""File extension handling tester — WSTG-CONF-03."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-file-ext")

_HTTP_CONCURRENCY = 20

# ── Extension categories ──────────────────────────────────────────────────────
NEVER_SERVE   = [".asa", ".inc", ".config"]
SOURCE_CODE   = [
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phps",
    ".asp", ".aspx", ".jsp", ".jspx", ".rb", ".py", ".pl", ".cgi",
]
CONFIGURATION = [
    ".xml", ".yml", ".yaml", ".ini", ".conf", ".cfg",
    ".properties", ".env", ".toml",
]
BACKUP   = [".bak", ".old", ".orig", ".swp", ".tmp", "~", ".backup", ".save"]
ARCHIVES = [".zip", ".tar", ".gz", ".tgz", ".rar", ".7z"]
DATABASE = [".sql", ".db", ".sqlite", ".sqlite3", ".mdb"]
DOCUMENTS = [".txt", ".log"]

_EXTENSION_CATEGORIES: list[tuple[str, list[str]]] = [
    ("never_serve",   NEVER_SERVE),
    ("source_code",   SOURCE_CODE),
    ("configuration", CONFIGURATION),
    ("backup",        BACKUP),
    ("archive",       ARCHIVES),
    ("database",      DATABASE),
    ("document",      DOCUMENTS),
]

_WIN83_BYPASS_EXTS = [".PHP", ".PHT", ".ASP"]

_SOURCE_SYNTAX = [
    "<?php", "<?=",
    "<%@", "response.write",
    "<jsp:",
    "#!/usr/bin/env python", "#!/usr/bin/python",
    "#!/usr/bin/perl", "#!/usr/bin/env perl",
    "#!/usr/bin/ruby",
]

_CREDENTIAL_PATTERNS = [
    "password", "passwd", "api_key", "apikey", "secret", "token",
    "db_pass", "database_url", "mysql://", "postgres://",
    "connection_string", "private_key",
]

CURATED_STEMS = [
    "/index", "/default", "/config", "/configuration", "/database",
    "/db", "/app", "/application", "/admin", "/login", "/settings",
    "/setup", "/install", "/backup", "/data", "/api", "/web",
]


def _generate_short_name(stem: str) -> str:
    """Return the 8.3-style short-name prefix for a path stem.

    Returns '' for stems too short to yield a meaningful 6-char prefix.
    e.g. '/webconfig' -> 'WEBCON', '/ab' -> ''
    """
    name = os.path.basename(stem).upper()
    name = "".join(c for c in name if c.isalnum())
    if len(name) < 3:
        return ""
    return name[:6]


class FileExtensionTester(ConfigMgmtTool):
    """Test file extension handling per WSTG-CONF-03."""

    name = "file_extension_tester"

    # ── ABC stubs (never called — execute() is overridden) ────────────────────
    def build_command(self, target, headers=None):
        raise NotImplementedError("FileExtensionTester uses native async execute()")

    def parse_output(self, stdout):
        raise NotImplementedError("FileExtensionTester uses native async execute()")

    # ── Pure response analysis ────────────────────────────────────────────────
    @staticmethod
    def _analyze_response(
        url: str,
        stem: str,
        ext: str,
        category: str,
        resp: httpx.Response,
    ) -> dict | None:
        """Return a finding dict for an HTTP 200 response, or None to skip."""
        body_lower = resp.text.lower()
        content_type = resp.headers.get("content-type", "").lower()

        has_credentials = any(p in body_lower for p in _CREDENTIAL_PATTERNS)

        if has_credentials or category == "database":
            severity = "critical"
        elif category == "never_serve":
            severity = "high"
        elif category == "source_code":
            source_exposed = (
                any(p in body_lower for p in _SOURCE_SYNTAX)
                or "text/plain" in content_type
                or "application/octet-stream" in content_type
            )
            if not source_exposed:
                return None
            severity = "high"
        elif category == "archive":
            severity = "high"
        elif category in ("configuration", "backup"):
            severity = "medium"
        elif category == "document":
            if not has_credentials:
                return None
            severity = "medium"
        else:
            severity = "medium"

        description = (
            f"{url} returned HTTP 200. "
            f"The {category.replace('_', ' ')} file with extension {ext!r} "
            "should not be publicly accessible."
        )
        if has_credentials:
            description += " Response body contains credential patterns."

        return {
            "vulnerability": {
                "name": f"Accessible {category.replace('_', ' ')} file: {stem}{ext}",
                "severity": severity,
                "description": description,
                "location": url,
                "section_id": "WSTG-CONF-03",
            }
        }
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/unit/workers/config_mgmt/test_file_extension_tester.py -v
```

Expected: all 11 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/ workers/config_mgmt/tools/file_extension_tester.py
git commit -m "test(conf03): pure-function tests and layer for _generate_short_name + _analyze_response"
```

---

## Task 3: DB helpers — `_fetch_path_stems` and `_is_iis_detected`

**Files:**
- Modify: `tests/unit/workers/config_mgmt/test_file_extension_tester.py` (append tests)
- Modify: `workers/config_mgmt/tools/file_extension_tester.py` (add DB methods to class)

- [ ] **Step 1: Append DB helper tests to the test file**

Add the following to the **end** of `tests/unit/workers/config_mgmt/test_file_extension_tester.py`:

```python
# ── _fetch_path_stems ─────────────────────────────────────────────────────────

async def test_fetch_path_stems_extracts_unique_stems():
    tester = FileExtensionTester()
    mock_assets = [
        MagicMock(asset_value="https://example.com/admin/login.php"),
        MagicMock(asset_value="https://example.com/api/v1/users.json"),
        MagicMock(asset_value="https://example.com/admin/login.php"),  # duplicate
    ]
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = mock_assets
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    stems = await tester._fetch_path_stems(mock_session, target_id=1)

    assert "/admin/login" in stems
    assert "/api/v1/users" in stems
    assert stems.count("/admin/login") == 1  # deduplicated


async def test_fetch_path_stems_returns_empty_on_no_assets():
    tester = FileExtensionTester()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    stems = await tester._fetch_path_stems(mock_session, target_id=1)
    assert stems == []


# ── _is_iis_detected ──────────────────────────────────────────────────────────

async def test_is_iis_detected_true_when_asset_exists():
    tester = FileExtensionTester()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = MagicMock()  # non-None = found

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    assert await tester._is_iis_detected(mock_session, target_id=1) is True


async def test_is_iis_detected_false_when_no_asset():
    tester = FileExtensionTester()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    assert await tester._is_iis_detected(mock_session, target_id=1) is False
```

- [ ] **Step 2: Run to confirm the new tests fail**

```bash
pytest tests/unit/workers/config_mgmt/test_file_extension_tester.py::test_fetch_path_stems_extracts_unique_stems -v
```

Expected: `AttributeError: 'FileExtensionTester' object has no attribute '_fetch_path_stems'`

- [ ] **Step 3: Add the DB helper methods inside `FileExtensionTester`**

Append these two methods inside the `FileExtensionTester` class in `workers/config_mgmt/tools/file_extension_tester.py`, after `_analyze_response`:

```python
    # ── DB helpers ────────────────────────────────────────────────────────────
    async def _fetch_path_stems(self, session, target_id: int) -> list[str]:
        """Extract unique path stems from prior-stage asset discoveries."""
        stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type.in_(["url", "page", "endpoint"]),
        )
        result = await session.execute(stmt)
        stems: list[str] = []
        for asset in result.scalars().all():
            try:
                path = urlparse(asset.asset_value).path
                stem, _ = os.path.splitext(path)
                if stem and stem not in ("/", "") and stem not in stems:
                    stems.append(stem)
            except Exception:
                pass
        return stems

    async def _is_iis_detected(self, session, target_id: int) -> bool:
        """Return True if IIS was detected in the platform_config stage."""
        stmt = (
            select(Asset)
            .where(
                Asset.target_id == target_id,
                Asset.asset_type == "server_software",
                Asset.asset_value.ilike("%IIS%"),
            )
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none() is not None
```

- [ ] **Step 4: Run all tests to confirm they pass**

```bash
pytest tests/unit/workers/config_mgmt/test_file_extension_tester.py -v
```

Expected: all 15 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/workers/config_mgmt/test_file_extension_tester.py workers/config_mgmt/tools/file_extension_tester.py
git commit -m "feat(conf03): add DB helper methods _fetch_path_stems and _is_iis_detected with tests"
```

---

## Task 4: Full `execute()` and HTTP test matrix

**Files:**
- Modify: `tests/unit/workers/config_mgmt/test_file_extension_tester.py` (append integration test)
- Modify: `workers/config_mgmt/tools/file_extension_tester.py` (complete implementation)

- [ ] **Step 1: Append the integration test**

Add the following to the **end** of `tests/unit/workers/config_mgmt/test_file_extension_tester.py`:

```python
# ── execute() integration ─────────────────────────────────────────────────────

async def test_execute_returns_stats_with_findings(monkeypatch):
    """execute() finds /index.php returning raw source and reports a finding."""
    tester = FileExtensionTester()

    # Cooldown check → not in cooldown
    monkeypatch.setattr(tester, "check_cooldown", AsyncMock(return_value=False))

    # Global semaphore — acquire/release are no-ops
    mock_sem = MagicMock()
    mock_sem.acquire = AsyncMock()
    mock_sem.release = MagicMock()
    monkeypatch.setattr(
        "workers.config_mgmt.tools.file_extension_tester.get_semaphore",
        lambda _: mock_sem,
    )

    # push_task → no-op
    monkeypatch.setattr(
        "workers.config_mgmt.tools.file_extension_tester.push_task",
        AsyncMock(),
    )

    # get_session: shared mock for both DB-query call and job_state update call.
    # scalar_one_or_none() returns None for both (no assets, no job_state row).
    session = MagicMock()
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty_result = MagicMock()
    empty_result.scalars.return_value = empty_scalars
    empty_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=empty_result)
    session.commit = AsyncMock()

    def fake_get_session():
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=session)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    monkeypatch.setattr(
        "workers.config_mgmt.tools.file_extension_tester.get_session",
        fake_get_session,
    )

    # httpx.AsyncClient: /index.php returns PHP source; all other URLs return 404
    resp_php = MagicMock()
    resp_php.status_code = 200
    resp_php.text = "<?php echo 'hello'; ?>"
    resp_php.headers = {"content-type": "text/plain"}

    resp_404 = MagicMock()
    resp_404.status_code = 404
    resp_404.text = ""
    resp_404.headers = {"content-type": "text/html"}

    async def fake_get(url):
        return resp_php if url.endswith("/index.php") else resp_404

    mock_client = MagicMock()
    mock_client.get = fake_get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(
        "workers.config_mgmt.tools.file_extension_tester.httpx.AsyncClient",
        lambda **kwargs: mock_client,
    )

    # _process_result → always new (True)
    monkeypatch.setattr(tester, "_process_result", AsyncMock(return_value=True))

    target = MagicMock(target_value="https://example.com")
    stats = await tester.execute(
        target=target,
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )

    assert stats["found"] >= 1
    assert stats["new"] >= 1
    assert stats["in_scope"] >= 1
    assert stats["skipped_cooldown"] is False


async def test_execute_skips_on_cooldown(monkeypatch):
    tester = FileExtensionTester()
    monkeypatch.setattr(tester, "check_cooldown", AsyncMock(return_value=True))

    stats = await tester.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )

    assert stats == {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}
```

- [ ] **Step 2: Run to confirm the new tests fail**

```bash
pytest tests/unit/workers/config_mgmt/test_file_extension_tester.py::test_execute_returns_stats_with_findings -v
```

Expected: the base class `execute()` calls `build_command()` which raises `NotImplementedError`, causing the test to fail.

- [ ] **Step 3: Append the remaining methods to `FileExtensionTester`**

Append these methods inside the `FileExtensionTester` class in `workers/config_mgmt/tools/file_extension_tester.py`, after `_is_iis_detected`:

```python
    # ── Main lifecycle ────────────────────────────────────────────────────────
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
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 0,
                "message": f"{self.name} started",
            })

            target_url = getattr(target, "target_value", str(target))
            base_url = (
                target_url
                if target_url.startswith(("http://", "https://"))
                else f"https://{target_url}"
            )

            async with get_session() as session:
                db_stems = await self._fetch_path_stems(session, target_id)
                iis_detected = await self._is_iis_detected(session, target_id)

            path_stems = list(dict.fromkeys(db_stems + CURATED_STEMS))
            findings = await self._run_test_matrix(base_url, path_stems, iis_detected, headers)

            found = len(findings)
            new_count = in_scope_count = 0
            for finding in findings:
                inserted = await self._process_result(finding, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
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
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": (
                    f"{self.name}: {new_count} new, "
                    f"{in_scope_count} in scope, {found} total"
                ),
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()

    # ── HTTP test matrix ──────────────────────────────────────────────────────
    async def _run_test_matrix(
        self,
        base_url: str,
        path_stems: list[str],
        iis_detected: bool,
        headers: dict | None,
    ) -> list[dict]:
        """Run all extension probes concurrently, return list of findings."""
        inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)
        tasks: list = []

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=10,
            headers=headers or {},
        ) as client:
            for stem in path_stems:
                for category, exts in _EXTENSION_CATEGORIES:
                    for ext in exts:
                        tasks.append(
                            self._probe(client, inner_sem, base_url, stem, ext, category)
                        )

            if iis_detected:
                for stem in path_stems:
                    short = _generate_short_name(stem)
                    if short:
                        for bypass_ext in _WIN83_BYPASS_EXTS:
                            url = base_url.rstrip("/") + "/" + short + "~1" + bypass_ext
                            tasks.append(self._probe_win83(client, inner_sem, url))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if r is not None and not isinstance(r, Exception)]

    async def _probe(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        base_url: str,
        stem: str,
        ext: str,
        category: str,
    ) -> dict | None:
        url = base_url.rstrip("/") + stem + ext
        async with sem:
            try:
                resp = await client.get(url)
            except (httpx.RequestError, asyncio.TimeoutError):
                return None

        if resp.status_code != 200:
            return None

        return self._analyze_response(url, stem, ext, category, resp)

    async def _probe_win83(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
    ) -> dict | None:
        async with sem:
            try:
                resp = await client.get(url)
            except (httpx.RequestError, asyncio.TimeoutError):
                return None

        if resp.status_code != 200:
            return None

        return {
            "vulnerability": {
                "name": f"Windows 8.3 filename bypass: {url}",
                "severity": "high",
                "description": (
                    f"{url} returned HTTP 200 via Windows 8.3 short filename. "
                    "Access controls on the canonical path may be bypassed."
                ),
                "location": url,
                "section_id": "WSTG-CONF-03",
            }
        }
```

- [ ] **Step 4: Run the full test suite**

```bash
pytest tests/unit/workers/config_mgmt/test_file_extension_tester.py -v
```

Expected: all 17 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/workers/config_mgmt/test_file_extension_tester.py workers/config_mgmt/tools/file_extension_tester.py
git commit -m "feat(conf03): complete FileExtensionTester rewrite — WSTG-CONF-03 aligned"
```
