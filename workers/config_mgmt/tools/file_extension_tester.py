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
    "<%", "<%@", "response.write",
    "<jsp:",
    "{%", "{{",
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
            severity = "critical"
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
            except (AttributeError, TypeError, ValueError):
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
            except httpx.RequestError:
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
            except httpx.RequestError:
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
