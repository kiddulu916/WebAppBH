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
