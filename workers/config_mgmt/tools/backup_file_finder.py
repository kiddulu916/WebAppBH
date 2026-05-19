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
    has_source = any(p in body_lower for p in _SOURCE_SYNTAX)

    if has_credentials:
        severity = "critical"
    elif has_source:
        severity = "high"
    else:
        severity = base_severity

    desc = (
        f"{url} returned HTTP {status_code}. "
        f"The {category.replace('_', ' ')} resource should not be publicly accessible."
    )
    if has_credentials:
        desc += " Response body contains credential patterns."
    elif has_source:
        desc += " Response body contains source code syntax."

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

    if has_credentials:
        severity = "critical"
    elif has_source:
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
    elif has_source:
        desc += " Response body contains source code syntax."

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
