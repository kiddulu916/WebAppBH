# WSTG-CONF-04: Backup and Unreferenced Files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `BackupFileFinder` as a pure async httpx tool with 5-phase WSTG-CONF-04 probing, and extend `FfufTool` with multi-directory fuzzing, supplemental wordlist injection, and backup-aware severity classification.

**Architecture:** `BackupFileFinder` overrides `execute()` entirely (same pattern as `FileExtensionTester`) — `build_command`/`parse_output` become NotImplementedError stubs. `FfufTool` also overrides `execute()` to manage multiple ffuf invocations (one per target directory) and a DB-derived supplemental wordlist. Both tools write `section_id = "WSTG-CONF-04"` on all vulnerability rows.

**Tech Stack:** Python 3.12, httpx (async), asyncio, SQLAlchemy async, pytest with `asyncio_mode = auto`, unittest.mock.

**Spec:** `docs/superpowers/specs/2026-05-19-wstg-conf-04-backup-files-design.md`

---

## File Map

| File | Change |
|---|---|
| `workers/config_mgmt/tools/backup_file_finder.py` | Full rewrite |
| `workers/config_mgmt/tools/ffuf_tool.py` | Extend — override execute(), add helpers |
| `tests/unit/workers/config_mgmt/test_backup_file_finder.py` | New |
| `tests/unit/workers/config_mgmt/test_ffuf_tool.py` | New |

No other files change.

---

## Task 1: BackupFileFinder — write failing pure-function tests

**Files:**
- Create: `tests/unit/workers/config_mgmt/test_backup_file_finder.py`

- [ ] **Step 1: Write the failing test file**

```python
"""Unit tests for WSTG-CONF-04 BackupFileFinder pure functions."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from workers.config_mgmt.tools.backup_file_finder import (
    BackupFileFinder,
    _analyze_mutation,
    _analyze_static_probe,
    _extract_directories,
    _extract_domain,
    _extract_path_pairs,
    _generate_mutations,
    _parse_robots_txt,
)


# ── _extract_path_pairs ───────────────────────────────────────────────────────

def test_extract_path_pairs_returns_stem_ext_tuples():
    result = _extract_path_pairs(["https://example.com/login.php"])
    assert ("/login", ".php") in result


def test_extract_path_pairs_deduplicates():
    result = _extract_path_pairs([
        "https://example.com/login.php",
        "https://example.com/login.php",
    ])
    assert result.count(("/login", ".php")) == 1


def test_extract_path_pairs_skips_bare_paths_without_extension():
    result = _extract_path_pairs(["https://example.com/api/v1"])
    assert result == []


def test_extract_path_pairs_skips_root():
    result = _extract_path_pairs(["https://example.com/"])
    assert result == []


# ── _generate_mutations ───────────────────────────────────────────────────────

def test_generate_mutations_includes_ext_plus_bak():
    result = _generate_mutations("/login", ".php")
    assert "/login.php.bak" in result


def test_generate_mutations_includes_tilde():
    result = _generate_mutations("/login", ".php")
    assert "/login.php~" in result


def test_generate_mutations_includes_bare_stem_bak():
    result = _generate_mutations("/login", ".php")
    assert "/login.bak" in result


def test_generate_mutations_includes_bare_stem_old():
    result = _generate_mutations("/login", ".php")
    assert "/login.old" in result


def test_generate_mutations_count():
    # 11 suffixes appended to stem+ext + 2 bare-stem variants = 13
    assert len(_generate_mutations("/config", ".yml")) == 13


# ── _extract_directories ──────────────────────────────────────────────────────

def test_extract_directories_returns_parent_dir():
    result = _extract_directories(["https://example.com/app/admin/login.php"])
    assert "/app/admin" in result


def test_extract_directories_deduplicates():
    result = _extract_directories([
        "https://example.com/app/admin/login.php",
        "https://example.com/app/admin/dashboard.php",
    ])
    assert result.count("/app/admin") == 1


def test_extract_directories_skips_root_files():
    result = _extract_directories(["https://example.com/index.php"])
    assert result == []


# ── _extract_domain ───────────────────────────────────────────────────────────

def test_extract_domain_from_https_url():
    assert _extract_domain("https://example.com/path") == "example.com"


def test_extract_domain_from_bare_hostname():
    assert _extract_domain("example.com") == "example.com"


def test_extract_domain_from_hostname_with_port():
    assert _extract_domain("example.com:8080") == "example.com"


def test_extract_domain_from_http_url():
    assert _extract_domain("http://sub.example.com") == "sub.example.com"


# ── _parse_robots_txt ─────────────────────────────────────────────────────────

def test_parse_robots_txt_extracts_disallow_paths():
    body = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
    result = _parse_robots_txt(body)
    assert "/admin" in result
    assert "/backup" in result


def test_parse_robots_txt_skips_root_disallow():
    body = "Disallow: /\n"
    result = _parse_robots_txt(body)
    assert result == []


def test_parse_robots_txt_handles_empty_disallow():
    body = "Disallow: \n"
    result = _parse_robots_txt(body)
    assert result == []


def test_parse_robots_txt_case_insensitive():
    body = "DISALLOW: /secret\n"
    result = _parse_robots_txt(body)
    assert "/secret" in result


# ── _analyze_static_probe ─────────────────────────────────────────────────────

def test_analyze_static_probe_env_200_is_high():
    result = _analyze_static_probe(
        "https://example.com/.env", "/.env", 200, "", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-04"


def test_analyze_static_probe_db_dump_200_is_critical():
    result = _analyze_static_probe(
        "https://example.com/dump.sql", "/dump.sql", 200, "-- SQL dump", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_static_probe_credentials_upgrade_to_critical():
    result = _analyze_static_probe(
        "https://example.com/.env", "/.env", 200, "password=secret123", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_static_probe_source_control_dir_403_is_observation():
    result = _analyze_static_probe(
        "https://example.com/.git/", "/.git/", 403, "", "text/html"
    )
    assert result is not None
    assert "observation" in result
    assert result["observation"]["type"] == "backup_access_denied"


def test_analyze_static_probe_source_control_dir_200_is_vulnerability():
    result = _analyze_static_probe(
        "https://example.com/.git/", "/.git/", 200, "ref: refs/heads/main", "text/plain"
    )
    assert result is not None
    assert "vulnerability" in result


def test_analyze_static_probe_404_returns_none():
    result = _analyze_static_probe(
        "https://example.com/.env", "/.env", 404, "", "text/html"
    )
    assert result is None


def test_analyze_static_probe_unknown_path_returns_none():
    result = _analyze_static_probe(
        "https://example.com/unknown.xyz", "/unknown.xyz", 200, "", "text/html"
    )
    assert result is None


# ── _analyze_mutation ─────────────────────────────────────────────────────────

def test_analyze_mutation_200_is_high():
    result = _analyze_mutation(
        "https://example.com/login.php.bak", "/login", ".php", 200, "", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-04"


def test_analyze_mutation_credentials_upgrade_to_critical():
    result = _analyze_mutation(
        "https://example.com/config.php.bak", "/config", ".php",
        200, "password=secret", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_mutation_404_returns_none():
    result = _analyze_mutation(
        "https://example.com/login.php.bak", "/login", ".php", 404, "", "text/html"
    )
    assert result is None


# ── execute() smoke tests ─────────────────────────────────────────────────────

async def test_execute_skips_on_cooldown(monkeypatch):
    tool = BackupFileFinder()
    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )
    assert stats == {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}


async def test_execute_returns_stats_on_finding(monkeypatch):
    tool = BackupFileFinder()

    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=False))

    mock_sem = MagicMock()
    mock_sem.acquire = AsyncMock()
    mock_sem.release = MagicMock()
    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.get_semaphore",
        lambda _: mock_sem,
    )
    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.push_task",
        AsyncMock(),
    )

    # DB session: returns empty asset list and no job state
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
        "workers.config_mgmt.tools.backup_file_finder.get_session",
        fake_get_session,
    )

    # httpx.AsyncClient: /.env returns 200 with a password; all else 404
    resp_env = MagicMock()
    resp_env.status_code = 200
    resp_env.text = "password=hunter2"
    resp_env.headers = {"content-type": "text/plain"}

    resp_404 = MagicMock()
    resp_404.status_code = 404
    resp_404.text = ""
    resp_404.headers = {"content-type": "text/html"}

    async def fake_get(url):
        return resp_env if url.endswith("/.env") else resp_404

    async def fake_head(url):
        return resp_404

    mock_client = MagicMock()
    mock_client.get = fake_get
    mock_client.head = fake_head
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.httpx.AsyncClient",
        lambda **kwargs: mock_client,
    )

    monkeypatch.setattr(tool, "_process_result", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )

    assert stats["found"] >= 1
    assert stats["new"] >= 1
    assert stats["skipped_cooldown"] is False
```

- [ ] **Step 2: Run tests to verify they all fail with ImportError**

```
pytest tests/unit/workers/config_mgmt/test_backup_file_finder.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` — module doesn't exist yet.

---

## Task 2: BackupFileFinder — implement pure functions and constants

**Files:**
- Write: `workers/config_mgmt/tools/backup_file_finder.py`

- [ ] **Step 1: Write the new backup_file_finder.py**

Replace the entire file with:

```python
"""Backup and unreferenced file discovery tool — WSTG-CONF-04."""

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

logger = setup_logger("config-mgmt-backup")

_HTTP_CONCURRENCY = 20

# ── Sensitive content patterns ────────────────────────────────────────────────

_SOURCE_SYNTAX = [
    "<?php", "<?=", "<%", "<%@", "response.write",
    "<jsp:", "{%", "{{",
    "#!/usr/bin/env python", "#!/usr/bin/python",
    "#!/usr/bin/perl", "#!/usr/bin/env perl",
    "#!/usr/bin/ruby",
]

_CREDENTIAL_PATTERNS = [
    "password", "passwd", "api_key", "apikey", "secret", "token",
    "db_pass", "database_url", "mysql://", "postgres://",
    "connection_string", "private_key",
]

_SCRIPT_EXTS = frozenset({
    ".php", ".php3", ".php4", ".php5", ".phtml", ".asp", ".aspx",
    ".jsp", ".rb", ".py", ".pl", ".cgi",
})

# ── Static probe registry ─────────────────────────────────────────────────────

_SOURCE_CONTROL_DIRS = frozenset({"/.git/", "/.svn/", "/.hg/", "/.bzr/"})

# path → (category, base_severity)
_STATIC_PROBES: dict[str, tuple[str, str]] = {
    "/.git/HEAD":              ("source_control", "high"),
    "/.git/config":            ("source_control", "high"),
    "/.git/index":             ("source_control", "high"),
    "/.git/":                  ("source_control", "high"),
    "/.svn/entries":           ("source_control", "high"),
    "/.svn/":                  ("source_control", "high"),
    "/.hg/":                   ("source_control", "high"),
    "/.bzr/":                  ("source_control", "high"),
    "/.env":                   ("env_secrets",    "high"),
    "/.env.local":             ("env_secrets",    "high"),
    "/.env.production":        ("env_secrets",    "high"),
    "/.env.development":       ("env_secrets",    "high"),
    "/.env.bak":               ("env_secrets",    "high"),
    "/.env.old":               ("env_secrets",    "high"),
    "/.htaccess":              ("server_config",  "high"),
    "/.htpasswd":              ("server_config",  "high"),
    "/web.config":             ("server_config",  "high"),
    "/web.config.bak":         ("server_config",  "high"),
    "/.DS_Store":              ("metadata",       "medium"),
    "/crossdomain.xml":        ("metadata",       "low"),
    "/clientaccesspolicy.xml": ("metadata",       "low"),
    "/index.php~":             ("editor_backup",  "high"),
    "/index.php.bak":          ("editor_backup",  "high"),
    "/index.php.old":          ("editor_backup",  "high"),
    "/index.php.orig":         ("editor_backup",  "high"),
    "/index.php.swp":          ("editor_backup",  "high"),
    "/config.php.bak":         ("editor_backup",  "high"),
    "/wp-config.php.bak":      ("editor_backup",  "high"),
    "/settings.py.bak":        ("editor_backup",  "high"),
    "/dump.sql":               ("db_dump",        "critical"),
    "/dump.sql.gz":            ("db_dump",        "critical"),
    "/backup.sql":             ("db_dump",        "critical"),
    "/database.sql":           ("db_dump",        "critical"),
    "/db.sql":                 ("db_dump",        "critical"),
    "/export.sql":             ("db_dump",        "critical"),
    "/mysqldump.sql":          ("db_dump",        "critical"),
    "/pg_dump.sql":            ("db_dump",        "critical"),
    "/config.bak":             ("config_backup",  "medium"),
    "/config.old":             ("config_backup",  "medium"),
    "/config.yml.bak":         ("config_backup",  "medium"),
    "/config.yaml.bak":        ("config_backup",  "medium"),
    "/config.ini.bak":         ("config_backup",  "medium"),
    "/application.yml.bak":    ("config_backup",  "medium"),
    "/settings.json.bak":      ("config_backup",  "medium"),
    "/.dockerignore":          ("deployment",     "medium"),
    "/Dockerfile":             ("deployment",     "medium"),
    "/docker-compose.yml":     ("deployment",     "medium"),
    "/Makefile":               ("deployment",     "medium"),
    "/package.json":           ("deployment",     "medium"),
    "/requirements.txt":       ("deployment",     "medium"),
    "/composer.json":          ("deployment",     "medium"),
    "/pom.xml":                ("deployment",     "medium"),
    "/go.mod":                 ("deployment",     "medium"),
}

# ── Probe configuration ───────────────────────────────────────────────────────

_MUTATION_SUFFIXES = [
    ".bak", "~", ".old", ".orig", ".swp",
    ".copy", ".tmp", ".src", ".dev", ".inc", ".txt",
]

_DIR_BACKUP_SUFFIXES = ["_backup", "_bak", ".old", "_old", ".backup"]

_GENERIC_ARCHIVES = [
    "/backup.zip",   "/backup.tar.gz", "/backup.tgz",
    "/www.zip",      "/www.tar.gz",
    "/site.zip",     "/site.tar.gz",
    "/web.zip",      "/web.tar.gz",
    "/htdocs.zip",   "/public_html.zip",
]


# ── Pure functions ────────────────────────────────────────────────────────────

def _extract_path_pairs(asset_values: list[str]) -> list[tuple[str, str]]:
    """Extract unique (stem, ext) pairs from a list of asset URL strings."""
    seen: set[tuple[str, str]] = set()
    pairs: list[tuple[str, str]] = []
    for value in asset_values:
        try:
            path = urlparse(value).path
            stem, ext = os.path.splitext(path)
            if ext and stem and stem not in ("/", ""):
                key = (stem, ext)
                if key not in seen:
                    seen.add(key)
                    pairs.append(key)
        except (AttributeError, TypeError, ValueError):
            pass
    return pairs


def _generate_mutations(stem: str, ext: str) -> list[str]:
    """Return 13 backup path variants for a (stem, ext) pair."""
    variants = [stem + ext + suffix for suffix in _MUTATION_SUFFIXES]
    variants.append(stem + ".bak")
    variants.append(stem + ".old")
    return variants


def _extract_directories(asset_values: list[str]) -> list[str]:
    """Extract unique parent directory paths from asset URL strings."""
    seen: set[str] = set()
    dirs: list[str] = []
    for value in asset_values:
        try:
            path = urlparse(value).path
            parent = os.path.dirname(path)
            if parent and parent not in ("/", ""):
                if parent not in seen:
                    seen.add(parent)
                    dirs.append(parent)
        except (AttributeError, TypeError, ValueError):
            pass
    return dirs


def _extract_domain(target_value: str) -> str:
    """Return the bare hostname from a target value string."""
    if "://" in target_value:
        return urlparse(target_value).hostname or ""
    return target_value.split("/")[0].split(":")[0]


def _parse_robots_txt(body: str) -> list[str]:
    """Extract Disallow paths from a robots.txt body string."""
    paths: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line[len("disallow:"):].strip()
            if path and path != "/":
                paths.append(path)
    return paths


def _analyze_static_probe(
    url: str,
    path: str,
    status_code: int,
    body: str,
    content_type: str,
) -> dict | None:
    """Return a finding dict for a static probe response, or None to skip."""
    entry = _STATIC_PROBES.get(path)
    if entry is None:
        return None
    category, base_severity = entry

    is_dir_probe = path in _SOURCE_CONTROL_DIRS
    if is_dir_probe:
        if status_code not in (200, 403):
            return None
    else:
        if status_code != 200:
            return None

    if status_code == 403:
        return {
            "observation": {
                "type": "backup_access_denied",
                "value": url,
                "details": {"path": path, "status": 403},
            }
        }

    body_lower = body.lower()
    has_credentials = any(p in body_lower for p in _CREDENTIAL_PATTERNS)
    severity = "critical" if has_credentials else base_severity

    desc = (
        f"{url} returned HTTP {status_code}. "
        f"The {category.replace('_', ' ')} resource should not be publicly accessible."
    )
    if has_credentials:
        desc += " Response body contains credential patterns."

    return {
        "vulnerability": {
            "name": f"Exposed {category.replace('_', ' ')}: {path}",
            "severity": severity,
            "description": desc,
            "location": url,
            "section_id": "WSTG-CONF-04",
        }
    }


def _analyze_mutation(
    url: str,
    stem: str,
    original_ext: str,
    status_code: int,
    body: str,
    content_type: str,
) -> dict | None:
    """Return a finding dict for a dynamic mutation probe, or None to skip."""
    if status_code != 200:
        return None

    body_lower = body.lower()
    has_credentials = any(p in body_lower for p in _CREDENTIAL_PATTERNS)
    has_source = any(p in body_lower for p in _SOURCE_SYNTAX)
    is_plain = "text/plain" in content_type or "application/octet-stream" in content_type

    if has_credentials:
        severity = "critical"
    elif original_ext in _SCRIPT_EXTS and (has_source or is_plain):
        severity = "high"
    else:
        severity = "high"

    filename = url.rsplit("/", 1)[-1] or url
    desc = (
        f"{url} returned HTTP 200. "
        f"Backup variant of {stem}{original_ext} is publicly accessible."
    )
    if has_credentials:
        desc += " Response body contains credential patterns."

    return {
        "vulnerability": {
            "name": f"Accessible backup file: {filename}",
            "severity": severity,
            "description": desc,
            "location": url,
            "section_id": "WSTG-CONF-04",
        }
    }


# ── Tool class ────────────────────────────────────────────────────────────────

class BackupFileFinder(ConfigMgmtTool):
    """Find backup and unreferenced files — WSTG-CONF-04."""

    name = "backup_file_finder"

    # ABC stubs — execute() is overridden; these are never called.
    def build_command(self, target, headers=None):
        raise NotImplementedError("BackupFileFinder uses native async execute()")

    def parse_output(self, stdout):
        raise NotImplementedError("BackupFileFinder uses native async execute()")

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _fetch_discovered_paths(self, session, target_id: int) -> list[str]:
        stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type.in_(["url", "page", "endpoint"]),
        )
        result = await session.execute(stmt)
        return [a.asset_value for a in result.scalars().all()]

    # ── Async probe methods ───────────────────────────────────────────────────

    async def _probe_static(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        base_url: str,
        path: str,
    ) -> dict | None:
        url = base_url.rstrip("/") + path
        async with sem:
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                return None
        return _analyze_static_probe(
            url, path, resp.status_code,
            resp.text, resp.headers.get("content-type", ""),
        )

    async def _probe_mutation(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        base_url: str,
        mutation_path: str,
        stem: str,
        original_ext: str,
    ) -> dict | None:
        url = base_url.rstrip("/") + mutation_path
        async with sem:
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                return None
        return _analyze_mutation(
            url, stem, original_ext, resp.status_code,
            resp.text, resp.headers.get("content-type", ""),
        )

    async def _probe_dir_variant(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        base_url: str,
        dir_path: str,
        suffix: str,
    ) -> dict | None:
        url = base_url.rstrip("/") + dir_path.rstrip("/") + suffix + "/"
        async with sem:
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                return None

        if resp.status_code == 200:
            return {
                "vulnerability": {
                    "name": f"Accessible directory backup: {dir_path}{suffix}",
                    "severity": "medium",
                    "description": (
                        f"{url} returned HTTP 200. "
                        "Directory backup variant is accessible."
                    ),
                    "location": url,
                    "section_id": "WSTG-CONF-04",
                }
            }
        if resp.status_code == 403:
            return {
                "observation": {
                    "type": "backup_access_denied",
                    "value": url,
                    "details": {"path": dir_path + suffix, "status": 403},
                }
            }
        return None

    async def _probe_archive(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        base_url: str,
        path: str,
    ) -> dict | None:
        url = base_url.rstrip("/") + path
        async with sem:
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                return None

        if resp.status_code != 200:
            return None

        body_lower = resp.text.lower()
        has_credentials = any(p in body_lower for p in _CREDENTIAL_PATTERNS)
        severity = "critical" if has_credentials else "high"

        return {
            "vulnerability": {
                "name": f"Accessible archive file: {path}",
                "severity": severity,
                "description": f"{url} returned HTTP 200. Archive file is publicly accessible.",
                "location": url,
                "section_id": "WSTG-CONF-04",
            }
        }

    async def _probe_robots_path(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        base_url: str,
        path: str,
    ) -> dict | None:
        url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        async with sem:
            try:
                resp = await client.head(url)
            except httpx.RequestError:
                return None

        if resp.status_code == 200:
            return {
                "vulnerability": {
                    "name": f"Accessible robots.txt disallowed path: {path}",
                    "severity": "low",
                    "description": (
                        f"{url} is listed in robots.txt Disallow but returned HTTP 200. "
                        "The path is accessible despite being disallowed."
                    ),
                    "location": url,
                    "section_id": "WSTG-CONF-04",
                }
            }
        if resp.status_code == 403:
            return {
                "observation": {
                    "type": "backup_access_denied",
                    "value": url,
                    "details": {"path": path, "status": 403},
                }
            }
        return None

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
                target_url if target_url.startswith(("http://", "https://"))
                else f"https://{target_url}"
            )
            domain = _extract_domain(target_url)

            # Phase 0 — DB reads
            async with get_session() as session:
                asset_values = await self._fetch_discovered_paths(session, target_id)

            path_pairs = _extract_path_pairs(asset_values)
            discovered_dirs = _extract_directories(asset_values)

            # Fetch robots.txt for Phase 5
            robots_paths: list[str] = []
            async with httpx.AsyncClient(verify=False, timeout=10) as prep_client:
                try:
                    robots_resp = await prep_client.get(
                        base_url.rstrip("/") + "/robots.txt"
                    )
                    if robots_resp.status_code == 200:
                        robots_paths = _parse_robots_txt(robots_resp.text)
                except httpx.RequestError:
                    pass

            # Domain-named archives for Phase 4
            domain_archives: list[str] = []
            if domain:
                name = domain.split(".")[0]
                domain_archives = [
                    f"/{domain}.zip", f"/{domain}.tar.gz",
                    f"/{name}.zip", f"/{name}.tar.gz",
                ]

            inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)
            tasks: list = []

            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=False,
                timeout=10,
                headers=headers or {},
            ) as client:
                # Phase 1: Static probes
                for path in _STATIC_PROBES:
                    tasks.append(self._probe_static(client, inner_sem, base_url, path))

                # Phase 2: Dynamic mutation from discovered paths
                for stem, ext in path_pairs:
                    for mutation in _generate_mutations(stem, ext):
                        tasks.append(
                            self._probe_mutation(
                                client, inner_sem, base_url, mutation, stem, ext
                            )
                        )

                # Phase 3: Directory backup variants
                for dir_path in discovered_dirs:
                    for suffix in _DIR_BACKUP_SUFFIXES:
                        tasks.append(
                            self._probe_dir_variant(
                                client, inner_sem, base_url, dir_path, suffix
                            )
                        )

                # Phase 4: Archive probing
                for path in _GENERIC_ARCHIVES + domain_archives:
                    tasks.append(self._probe_archive(client, inner_sem, base_url, path))

                # Phase 5: robots.txt disallowed paths
                for path in robots_paths:
                    tasks.append(
                        self._probe_robots_path(client, inner_sem, base_url, path)
                    )

                results = await asyncio.gather(*tasks, return_exceptions=True)

            findings = [
                r for r in results
                if r is not None and not isinstance(r, Exception)
            ]
            found = len(findings)
            new_count = in_scope_count = 0
            for finding in findings:
                inserted = await self._process_result(
                    finding, scope_manager, target_id, log
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
```

- [ ] **Step 2: Run the pure-function tests from Task 1**

```
pytest tests/unit/workers/config_mgmt/test_backup_file_finder.py -v -k "not execute"
```

Expected: All pure-function tests PASS.

- [ ] **Step 3: Run the execute() smoke tests**

```
pytest tests/unit/workers/config_mgmt/test_backup_file_finder.py -v -k "execute"
```

Expected: Both execute() tests PASS.

- [ ] **Step 4: Run the full unit test suite to check for regressions**

```
pytest tests/unit/ -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/config_mgmt/tools/backup_file_finder.py \
        tests/unit/workers/config_mgmt/test_backup_file_finder.py
git commit -m "feat(conf04): rewrite BackupFileFinder as async httpx 5-phase tool"
```

---

## Task 3: FfufTool — write failing pure-function tests

**Files:**
- Create: `tests/unit/workers/config_mgmt/test_ffuf_tool.py`

- [ ] **Step 1: Write the failing test file**

```python
"""Unit tests for extended FfufTool (WSTG-CONF-04)."""

from unittest.mock import AsyncMock, MagicMock, patch
import os
import json
import tempfile

import pytest

from workers.config_mgmt.tools.ffuf_tool import (
    FfufTool,
    _build_supplemental_wordlist,
    _classify_ffuf_result,
    _extract_dir_paths,
    _parse_ffuf_file,
    _build_ffuf_cmd,
)


# ── _extract_dir_paths ────────────────────────────────────────────────────────

def test_extract_dir_paths_returns_parent_dirs():
    result = _extract_dir_paths(["https://example.com/app/admin/login.php"])
    assert "/app/admin" in result


def test_extract_dir_paths_deduplicates():
    result = _extract_dir_paths([
        "https://example.com/app/admin/a.php",
        "https://example.com/app/admin/b.php",
    ])
    assert result.count("/app/admin") == 1


def test_extract_dir_paths_skips_root_files():
    result = _extract_dir_paths(["https://example.com/index.php"])
    assert result == []


# ── _build_supplemental_wordlist ──────────────────────────────────────────────

def test_build_supplemental_wordlist_returns_entries_for_extensions():
    result = _build_supplemental_wordlist([".php"])
    assert any(line.endswith(".bak") for line in result)
    assert any(".php" in line for line in result)


def test_build_supplemental_wordlist_caps_at_200():
    # Many extensions → hard cap at 200 entries
    extensions = [f".ext{i}" for i in range(50)]
    result = _build_supplemental_wordlist(extensions)
    assert len(result) <= 200


def test_build_supplemental_wordlist_empty_for_no_extensions():
    result = _build_supplemental_wordlist([])
    assert result == []


# ── _classify_ffuf_result ─────────────────────────────────────────────────────

def test_classify_ffuf_result_db_ext_is_critical():
    result = _classify_ffuf_result("/dump.sql", 200, "https://example.com/dump.sql")
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-04"


def test_classify_ffuf_result_backup_ext_is_high():
    result = _classify_ffuf_result("/config.php.bak", 200, "https://example.com/config.php.bak")
    assert result["vulnerability"]["severity"] == "high"


def test_classify_ffuf_result_tilde_is_high():
    result = _classify_ffuf_result("/index.php~", 200, "https://example.com/index.php~")
    assert result["vulnerability"]["severity"] == "high"


def test_classify_ffuf_result_archive_is_high():
    result = _classify_ffuf_result("/backup.zip", 200, "https://example.com/backup.zip")
    assert result["vulnerability"]["severity"] == "high"


def test_classify_ffuf_result_403_is_observation():
    result = _classify_ffuf_result("/admin", 403, "https://example.com/admin")
    assert "observation" in result
    assert result["observation"]["type"] == "ffuf_access_denied"


def test_classify_ffuf_result_generic_path_is_low():
    result = _classify_ffuf_result("/about", 200, "https://example.com/about")
    assert result["vulnerability"]["severity"] == "low"


# ── _parse_ffuf_file ──────────────────────────────────────────────────────────

def test_parse_ffuf_file_returns_results(tmp_path):
    data = {
        "results": [
            {"input": {"FUZZ": "config.php.bak"}, "status": 200, "url": "https://example.com/config.php.bak", "length": 512},
        ]
    }
    f = tmp_path / "ffuf_out.json"
    f.write_text(json.dumps(data))
    results = _parse_ffuf_file(str(f))
    assert len(results) == 1
    assert results[0]["path"] == "config.php.bak"
    assert results[0]["status"] == 200


def test_parse_ffuf_file_returns_empty_for_missing_file():
    results = _parse_ffuf_file("/tmp/nonexistent_ffuf_output.json")
    assert results == []


def test_parse_ffuf_file_deletes_file_after_reading(tmp_path):
    data = {"results": []}
    f = tmp_path / "ffuf_out.json"
    f.write_text(json.dumps(data))
    _parse_ffuf_file(str(f))
    assert not f.exists()


# ── _build_ffuf_cmd ───────────────────────────────────────────────────────────

def test_build_ffuf_cmd_basic_structure():
    cmd = _build_ffuf_cmd(
        url="https://example.com/FUZZ",
        wordlist="/wordlists/common.txt",
        output_file="/tmp/out.json",
        rate_limit=50,
        headers=None,
    )
    assert "ffuf" in cmd
    assert "https://example.com/FUZZ" in cmd
    assert "/wordlists/common.txt" in cmd
    assert "/tmp/out.json" in cmd
    assert "json" in cmd


def test_build_ffuf_cmd_includes_supplemental_wordlist():
    cmd = _build_ffuf_cmd(
        url="https://example.com/FUZZ",
        wordlist="/wordlists/common.txt",
        output_file="/tmp/out.json",
        rate_limit=50,
        headers=None,
        supplemental_wl="/tmp/supp.txt",
    )
    assert "/tmp/supp.txt" in cmd
    assert cmd.count("-w") >= 2


def test_build_ffuf_cmd_includes_headers():
    cmd = _build_ffuf_cmd(
        url="https://example.com/FUZZ",
        wordlist="/wordlists/common.txt",
        output_file="/tmp/out.json",
        rate_limit=50,
        headers={"X-API-KEY": "abc123"},
    )
    assert "X-API-KEY: abc123" in cmd


# ── execute() smoke tests ─────────────────────────────────────────────────────

async def test_ffuf_execute_skips_on_cooldown(monkeypatch):
    tool = FfufTool()
    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )
    assert stats == {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}


async def test_ffuf_execute_runs_and_returns_stats(monkeypatch):
    tool = FfufTool()

    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=False))

    mock_sem = MagicMock()
    mock_sem.acquire = AsyncMock()
    mock_sem.release = MagicMock()
    monkeypatch.setattr(
        "workers.config_mgmt.tools.ffuf_tool.get_semaphore",
        lambda _: mock_sem,
    )
    monkeypatch.setattr(
        "workers.config_mgmt.tools.ffuf_tool.push_task",
        AsyncMock(),
    )

    # DB: no discovered dirs/extensions
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

    monkeypatch.setattr("workers.config_mgmt.tools.ffuf_tool.get_session", fake_get_session)

    # run_subprocess: writes a ffuf JSON output file with one finding
    async def fake_run_subprocess(cmd, timeout=600):
        # find -o argument in cmd and write a fake result
        try:
            idx = cmd.index("-o")
            out_file = cmd[idx + 1]
            with open(out_file, "w") as f:
                json.dump({
                    "results": [
                        {
                            "input": {"FUZZ": "backup.zip"},
                            "status": 200,
                            "url": "https://example.com/backup.zip",
                            "length": 1024,
                        }
                    ]
                }, f)
        except (ValueError, IndexError):
            pass
        return ""

    monkeypatch.setattr(tool, "run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(tool, "_process_result", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )

    assert stats["found"] >= 1
    assert stats["skipped_cooldown"] is False
```

- [ ] **Step 2: Run tests to verify they fail with ImportError**

```
pytest tests/unit/workers/config_mgmt/test_ffuf_tool.py -v
```

Expected: `ImportError` — the new functions don't exist yet in `ffuf_tool.py`.

---

## Task 4: FfufTool — implement pure functions and extend execute()

**Files:**
- Write: `workers/config_mgmt/tools/ffuf_tool.py`

- [ ] **Step 1: Write the new ffuf_tool.py**

Replace the entire file with:

```python
"""Ffuf directory/file fuzzing tool for config management — WSTG-CONF-04."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass, get_semaphore

logger = setup_logger("config-mgmt-ffuf")

SMALL_WORDLIST = os.environ.get("WORDLIST_SMALL", "/app/wordlists/common.txt")
LARGE_WORDLIST = os.environ.get("WORDLIST_LARGE", "/app/wordlists/directory-list-2.3-medium.txt")
RATE_THRESHOLD = 50

# ── Severity classification constants ─────────────────────────────────────────

_FFUF_DB_EXTS      = frozenset({".sql", ".db", ".sqlite", ".sqlite3", ".mdb"})
_FFUF_BACKUP_EXTS  = frozenset({".bak", ".old", ".orig", ".swp", ".copy", ".tmp", ".src", ".dev", ".inc"})
_FFUF_ARCHIVE_EXTS = frozenset({".zip", ".tar", ".gz", ".tgz", ".rar", ".7z"})
_FFUF_SCRIPT_EXTS  = frozenset({".php", ".php3", ".php5", ".phtml", ".asp", ".aspx", ".jsp", ".rb", ".py", ".pl", ".cgi"})

_COMMON_STEMS = [
    "index", "config", "backup", "admin", "login",
    "app", "default", "web", "database", "settings",
]
_SUPPLEMENTAL_BACKUP_SUFFIXES = [
    ".bak", ".old", ".orig", "~", ".swp",
    ".copy", ".tmp", ".src", ".dev", ".inc",
]


# ── Pure functions ────────────────────────────────────────────────────────────

def _extract_dir_paths(asset_values: list[str]) -> list[str]:
    """Extract unique parent directory paths from asset URL strings."""
    seen: set[str] = set()
    dirs: list[str] = []
    for value in asset_values:
        try:
            path = urlparse(value).path
            parent = os.path.dirname(path)
            if parent and parent not in ("/", ""):
                if parent not in seen:
                    seen.add(parent)
                    dirs.append(parent)
        except (AttributeError, TypeError, ValueError):
            pass
    return dirs


def _build_supplemental_wordlist(extensions: list[str]) -> list[str]:
    """Build supplemental wordlist entries from discovered file extensions.

    Combines common stems with each discovered extension and every backup suffix.
    Capped at 200 entries to bound ffuf runtime.
    """
    lines: list[str] = []
    for ext in extensions:
        for stem in _COMMON_STEMS:
            for suffix in _SUPPLEMENTAL_BACKUP_SUFFIXES:
                lines.append(stem + ext + suffix)
                if len(lines) >= 200:
                    return lines
    return lines


def _classify_ffuf_result(path: str, status: int, url: str = "") -> dict:
    """Return a vulnerability or observation dict for one ffuf discovery."""
    _, ext = os.path.splitext(path.lower())
    has_tilde = "~" in path

    if status in (401, 403):
        return {
            "observation": {
                "type": "ffuf_access_denied",
                "value": url or path,
                "details": {"path": path, "status": status},
            }
        }

    if ext in _FFUF_DB_EXTS:
        severity = "critical"
    elif ext in _FFUF_BACKUP_EXTS or has_tilde:
        severity = "high"
    elif ext in _FFUF_ARCHIVE_EXTS:
        severity = "high"
    elif ext in _FFUF_SCRIPT_EXTS and status == 200:
        severity = "medium"
    else:
        severity = "low"

    return {
        "vulnerability": {
            "name": f"Discovered path: {path}",
            "severity": severity,
            "description": f"ffuf discovered {url or path} (HTTP {status}).",
            "location": url or path,
            "section_id": "WSTG-CONF-04",
        }
    }


def _parse_ffuf_file(output_file: str) -> list[dict]:
    """Parse a ffuf JSON output file; deletes the file afterwards."""
    if not os.path.exists(output_file):
        return []
    try:
        with open(output_file) as f:
            data = json.load(f)
        os.unlink(output_file)
        results = []
        for entry in data.get("results", []):
            path = entry.get("input", {}).get("FUZZ", "") or entry.get("url", "")
            status = entry.get("status", 0)
            url = entry.get("url", path)
            length = entry.get("length", 0)
            results.append({"path": path, "status": status, "url": url, "length": length})
        return results
    except (json.JSONDecodeError, OSError):
        if os.path.exists(output_file):
            os.unlink(output_file)
        return []


def _build_ffuf_cmd(
    url: str,
    wordlist: str,
    output_file: str,
    rate_limit: int,
    headers: dict | None,
    supplemental_wl: str | None = None,
) -> list[str]:
    """Build a ffuf command list for one target URL."""
    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-o", output_file, "-of", "json",
        "-mc", "200,204,301,302,307,401,403",
        "-rate", str(rate_limit),
        "-t", str(min(rate_limit, 50)),
    ]
    if supplemental_wl:
        cmd.extend(["-w", supplemental_wl])
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    return cmd


# ── Tool class ────────────────────────────────────────────────────────────────

class FfufTool(ConfigMgmtTool):
    """Directory and file fuzzing with ffuf — WSTG-CONF-04."""

    name = "FfufTool"

    @property
    def weight_class(self) -> WeightClass:
        return WeightClass.HEAVY

    # ABC stubs — execute() is overridden; these are never called.
    def build_command(self, target, headers=None):
        raise NotImplementedError("FfufTool uses native async execute()")

    def parse_output(self, stdout):
        raise NotImplementedError("FfufTool uses native async execute()")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _choose_wordlist(self, rate_limit: int) -> str:
        return LARGE_WORDLIST if rate_limit >= RATE_THRESHOLD else SMALL_WORDLIST

    async def _fetch_discovered_dirs(self, session, target_id: int) -> list[str]:
        stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type.in_(["url", "page", "endpoint", "directory"]),
        )
        result = await session.execute(stmt)
        return _extract_dir_paths([a.asset_value for a in result.scalars().all()])

    async def _fetch_discovered_extensions(self, session, target_id: int) -> list[str]:
        stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type.in_(["url", "page", "endpoint"]),
        )
        result = await session.execute(stmt)
        seen: set[str] = set()
        exts: list[str] = []
        for asset in result.scalars().all():
            try:
                _, ext = os.path.splitext(urlparse(asset.asset_value).path)
                if ext and ext not in seen:
                    seen.add(ext)
                    exts.append(ext)
            except (AttributeError, TypeError):
                pass
        return exts

    async def _run_ffuf_for_url(
        self,
        url: str,
        wordlist: str,
        rate_limit: int,
        headers: dict | None,
        supplemental_wl: str | None,
    ) -> list[dict]:
        """Run ffuf for one target URL and return parsed results."""
        output_file = tempfile.mktemp(suffix=".json", prefix="ffuf_")
        cmd = _build_ffuf_cmd(url, wordlist, output_file, rate_limit, headers, supplemental_wl)
        try:
            await self.run_subprocess(cmd)
        except (asyncio.TimeoutError, FileNotFoundError):
            pass
        return _parse_ffuf_file(output_file)

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
                target_url if target_url.startswith(("http://", "https://"))
                else f"https://{target_url}"
            )

            async with get_session() as session:
                discovered_dirs = await self._fetch_discovered_dirs(session, target_id)
                extensions = await self._fetch_discovered_extensions(session, target_id)

            rate_limit = int(os.environ.get("RATE_LIMIT", "50"))
            wordlist = self._choose_wordlist(rate_limit)

            # Build supplemental wordlist temp file (if extensions found)
            supp_wl_path: str | None = None
            supp_lines = _build_supplemental_wordlist(extensions)
            if supp_lines:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", prefix="ffuf_supp_", delete=False
                ) as f:
                    f.write("\n".join(supp_lines))
                    supp_wl_path = f.name

            # Target URLs: webroot + up to 10 discovered directories
            dir_paths = [""] + discovered_dirs[:10]

            all_raw: list[dict] = []
            try:
                for dir_path in dir_paths:
                    url = base_url.rstrip("/") + dir_path + "/FUZZ"
                    raw = await self._run_ffuf_for_url(
                        url, wordlist, rate_limit, headers, supp_wl_path
                    )
                    all_raw.extend(raw)
            finally:
                if supp_wl_path and os.path.exists(supp_wl_path):
                    os.unlink(supp_wl_path)

            findings = [
                _classify_ffuf_result(r["path"], r["status"], r["url"])
                for r in all_raw
            ]
            found = len(findings)
            new_count = in_scope_count = 0
            for finding in findings:
                inserted = await self._process_result(
                    finding, scope_manager, target_id, log
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
```

- [ ] **Step 2: Run the pure-function tests from Task 3**

```
pytest tests/unit/workers/config_mgmt/test_ffuf_tool.py -v -k "not execute"
```

Expected: All pure-function tests PASS.

- [ ] **Step 3: Run the execute() smoke tests**

```
pytest tests/unit/workers/config_mgmt/test_ffuf_tool.py -v -k "execute"
```

Expected: Both execute() tests PASS.

- [ ] **Step 4: Run the full unit suite to check for regressions**

```
pytest tests/unit/ -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/config_mgmt/tools/ffuf_tool.py \
        tests/unit/workers/config_mgmt/test_ffuf_tool.py
git commit -m "feat(conf04): extend FfufTool with multi-dir fuzzing, supplemental wordlist, severity classification"
```

---

## Task 5: Final verification

**Files:** No changes — verification only.

- [ ] **Step 1: Run the complete unit test suite**

```
pytest tests/unit/ -v
```

Expected: All tests PASS.

- [ ] **Step 2: Verify the stage is wired correctly in the pipeline**

Open `workers/config_mgmt/pipeline.py` and confirm:
```python
Stage("backup_files", [BackupFileFinder, FfufTool]),
```
Both tool classes are already imported and registered. No change needed.

- [ ] **Step 3: Verify playbooks.py lists the stage**

Open `shared/lib_webbh/playbooks.py` and confirm `"backup_files"` appears in the `config_mgmt` stage list. No change needed.

- [ ] **Step 4: Verify dashboard worker-stages.ts lists the stage**

Open `dashboard/src/lib/worker-stages.ts` and confirm:
```typescript
{ id: "4", name: "Backup Files", stageName: "backup_files", sectionId: "WSTG-CONF-04" },
```
No change needed.

- [ ] **Step 5: Commit**

No new commits needed if Step 1 passes and Steps 2-4 confirm no changes are required.
