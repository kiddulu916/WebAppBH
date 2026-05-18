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
