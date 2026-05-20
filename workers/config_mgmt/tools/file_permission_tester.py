"""File permission tester — WSTG-CONF-09."""

from __future__ import annotations

import asyncio
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf09")

_SECTION_ID = "WSTG-CONF-09"

_DIRECTORY_SIGNATURES = [
    "Index of",
    "Directory listing for",
    "Parent Directory",
    "[To Parent Directory]",
]

_DIRECTORY_PATHS = [
    "admin", "backup", "config", "logs", "uploads",
    "tmp", "test", "private", "data", "files",
    "src", "includes", "lib", "vendor",
]

_SENSITIVE_FILES: list[tuple[str, str]] = [
    (".env",                    "critical"),
    (".env.local",              "critical"),
    (".env.production",         "critical"),
    (".git/config",             "critical"),
    (".git/HEAD",               "high"),
    (".htpasswd",               "critical"),
    (".htaccess",               "medium"),
    ("web.config",              "high"),
    ("WEB-INF/web.xml",         "high"),
    ("WEB-INF/web.properties",  "high"),
    (".svn/entries",            "high"),
    ("server-status",           "medium"),
    ("server-info",             "medium"),
    ("phpinfo.php",             "medium"),
    (".DS_Store",               "low"),
    ("composer.json",           "low"),
    ("package.json",            "low"),
    ("docker-compose.yml",      "high"),
    ("Dockerfile",              "medium"),
    ("config.php",              "critical"),
    ("wp-config.php",           "critical"),
    ("database.php",            "critical"),
    ("settings.php",            "high"),
    (".bash_history",           "high"),
    (".ssh/id_rsa",             "critical"),
]


def _is_directory_listing(body: str) -> bool:
    """Return True if body contains any known directory-listing signature."""
    return any(sig in body for sig in _DIRECTORY_SIGNATURES)


def _classify_directory(url: str, status: int, body: str) -> dict | None:
    """Return a vuln or observation dict for a directory probe result, or None to skip."""
    if status == 200 and _is_directory_listing(body):
        return {"vulnerability": {
            "name": f"Directory listing enabled at {url}",
            "severity": "high",
            "description": (
                f"The directory at {url} has listing enabled, exposing its contents "
                "to unauthenticated visitors."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }}
    if status == 403:
        return {"observation": {
            "type": "directory_access",
            "value": "access_denied",
            "details": {"url": url, "status": status},
        }}
    return None


def _classify_sensitive_file(url: str, path: str, status: int, severity: str) -> dict | None:
    """Return a vuln dict if status is 200, else None."""
    if status != 200:
        return None
    return {"vulnerability": {
        "name": f"Sensitive file exposed: {path}",
        "severity": severity,
        "description": (
            f"The file {path} is publicly accessible at {url}. "
            "This file should be protected by filesystem or server permissions."
        ),
        "location": url,
        "section_id": _SECTION_ID,
    }}


async def _probe_directory(
    client: httpx.AsyncClient,
    base_url: str,
    dir_path: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    """GET {base_url}/{dir_path}/ and classify the response."""
    url = f"{base_url.rstrip('/')}/{dir_path}/"
    async with sem:
        try:
            resp = await client.get(url)
            return _classify_directory(url, resp.status_code, resp.text)
        except httpx.RequestError:
            return None


async def _probe_sensitive_file(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    severity: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    """GET {base_url}/{path} and classify the response."""
    url = f"{base_url.rstrip('/')}/{path}"
    async with sem:
        try:
            resp = await client.get(url)
            return _classify_sensitive_file(url, path, resp.status_code, severity)
        except httpx.RequestError:
            return None


class FilePermissionTester(ConfigMgmtTool):
    """Test file and directory permissions per WSTG-CONF-09.

    Phase 1: Detect directories with open listing.
    Phase 2: Probe known sensitive paths for HTTP 200 responses.
    """

    name = "file_permission_tester"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("FilePermissionTester uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("FilePermissionTester uses execute() directly")

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
            if not raw.startswith(("http://", "https://")):
                raw = f"https://{raw}"
            parsed_url = urlparse(raw)
            base_host = parsed_url.netloc or parsed_url.path
            base_url = f"{parsed_url.scheme}://{base_host}"

            if not scope_manager.is_in_scope(base_url).in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            all_results: list[dict] = []

            async with httpx.AsyncClient(
                verify=False, follow_redirects=False, timeout=10,
                headers=headers or {},
            ) as client:
                probe_sem = asyncio.Semaphore(10)

                # Phase 1 — directory listing
                p1_tasks = [
                    _probe_directory(client, base_url, d, probe_sem)
                    for d in _DIRECTORY_PATHS
                ]
                for r in await asyncio.gather(*p1_tasks, return_exceptions=True):
                    if isinstance(r, dict):
                        all_results.append(r)

                # Phase 2 — sensitive file exposure
                p2_tasks = [
                    _probe_sensitive_file(client, base_url, path, severity, probe_sem)
                    for path, severity in _SENSITIVE_FILES
                ]
                for r in await asyncio.gather(*p2_tasks, return_exceptions=True):
                    if isinstance(r, dict):
                        all_results.append(r)

            found = len(all_results)
            new_count = in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
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
            log.info(f"{self.name} complete", **stats)
            return stats

        finally:
            sem.release()
