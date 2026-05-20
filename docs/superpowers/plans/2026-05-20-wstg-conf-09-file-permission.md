# WSTG-CONF-09 File Permission Tester Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `FilePermissionTester` (WSTG-CONF-09) to the `config_mgmt` worker — a two-phase async httpx tool that detects open directory listings and exposed sensitive files, wired through all three coherence layers.

**Architecture:** Pure async `execute()` override (same pattern as `HstsTester`), with all classification logic in module-level pure functions so tests need no DB or network. New `file_permission` pipeline stage inserts after `rpc_testing` (CONF-08), preserving WSTG numeric order. Three-layer coherence update: `pipeline.py` + `playbooks.py` + `worker-stages.ts`.

**Tech Stack:** Python 3.12, httpx (async), asyncio, SQLAlchemy async, pytest (pure-function unit tests, no fixtures needed)

---

## File Map

| Action | File |
|--------|------|
| Create | `workers/config_mgmt/tools/file_permission_tester.py` |
| Create | `tests/unit/config_mgmt/test_file_permission_tester.py` |
| Modify | `workers/config_mgmt/tools/__init__.py` |
| Modify | `workers/config_mgmt/pipeline.py` |
| Modify | `workers/config_mgmt/concurrency.py` |
| Modify | `shared/lib_webbh/playbooks.py` |
| Modify | `dashboard/src/lib/worker-stages.ts` |

---

## Task 1: Write Failing Unit Tests

**Files:**
- Create: `tests/unit/config_mgmt/test_file_permission_tester.py`

- [ ] **Step 1.1: Write the test file**

Create `tests/unit/config_mgmt/test_file_permission_tester.py` with the following content:

```python
"""Unit tests for FilePermissionTester pure helper functions (WSTG-CONF-09)."""
from workers.config_mgmt.tools.file_permission_tester import (
    _SECTION_ID,
    _is_directory_listing,
    _classify_directory,
    _classify_sensitive_file,
)


def test_is_directory_listing_index_of():
    assert _is_directory_listing("<!DOCTYPE html><html><body>Index of /tmp</body></html>") is True


def test_is_directory_listing_parent_dir():
    assert _is_directory_listing("<a href=..>Parent Directory</a>") is True


def test_is_directory_listing_false():
    assert _is_directory_listing("<html><body><h1>Welcome</h1></body></html>") is False


def test_classify_directory_listing_high():
    url = "https://example.com/backup/"
    result = _classify_directory(url, 200, "Index of /backup")
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"
    assert result["vulnerability"]["location"] == url


def test_classify_directory_403():
    result = _classify_directory("https://example.com/admin/", 403, "")
    assert result is not None
    assert "observation" in result
    assert result["observation"]["type"] == "directory_access"
    assert result["observation"]["value"] == "access_denied"


def test_classify_directory_404():
    result = _classify_directory("https://example.com/secret/", 404, "")
    assert result is None


def test_classify_directory_200_no_listing():
    result = _classify_directory("https://example.com/app/", 200, "<html>Normal page</html>")
    assert result is None


def test_classify_sensitive_file_200_critical():
    result = _classify_sensitive_file("https://example.com/.env", ".env", 200, "critical")
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_sensitive_file_200_high():
    result = _classify_sensitive_file("https://example.com/web.config", "web.config", 200, "high")
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"


def test_classify_sensitive_file_200_medium():
    result = _classify_sensitive_file(
        "https://example.com/phpinfo.php", "phpinfo.php", 200, "medium"
    )
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "medium"


def test_classify_sensitive_file_200_low():
    result = _classify_sensitive_file(
        "https://example.com/composer.json", "composer.json", 200, "low"
    )
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "low"


def test_classify_sensitive_file_non_200():
    result = _classify_sensitive_file("https://example.com/.env", ".env", 404, "critical")
    assert result is None


def test_section_id_in_directory_vuln():
    result = _classify_directory("https://example.com/backup/", 200, "Index of /backup")
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-09"


def test_section_id_in_file_vuln():
    result = _classify_sensitive_file("https://example.com/.env", ".env", 200, "critical")
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-09"


def test_section_id_constant():
    assert _SECTION_ID == "WSTG-CONF-09"
```

- [ ] **Step 1.2: Run the tests — expect ImportError**

```bash
pytest tests/unit/config_mgmt/test_file_permission_tester.py -v
```

Expected: All 15 tests FAIL with `ModuleNotFoundError: No module named 'workers.config_mgmt.tools.file_permission_tester'`

---

## Task 2: Implement FilePermissionTester

**Files:**
- Create: `workers/config_mgmt/tools/file_permission_tester.py`

- [ ] **Step 2.1: Create the tool file**

Create `workers/config_mgmt/tools/file_permission_tester.py`:

```python
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
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
```

- [ ] **Step 2.2: Run tests — expect all 15 to pass**

```bash
pytest tests/unit/config_mgmt/test_file_permission_tester.py -v
```

Expected output (all 15 PASSED):
```
tests/unit/config_mgmt/test_file_permission_tester.py::test_is_directory_listing_index_of PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_is_directory_listing_parent_dir PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_is_directory_listing_false PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_directory_listing_high PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_directory_403 PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_directory_404 PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_directory_200_no_listing PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_sensitive_file_200_critical PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_sensitive_file_200_high PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_sensitive_file_200_medium PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_sensitive_file_200_low PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_classify_sensitive_file_non_200 PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_section_id_in_directory_vuln PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_section_id_in_file_vuln PASSED
tests/unit/config_mgmt/test_file_permission_tester.py::test_section_id_constant PASSED
```

- [ ] **Step 2.3: Commit**

```bash
git add workers/config_mgmt/tools/file_permission_tester.py \
        tests/unit/config_mgmt/test_file_permission_tester.py
git commit -m "feat(conf09): add FilePermissionTester with pure-function unit tests"
```

---

## Task 3: Wire Three-Layer Coherence

**Files:**
- Modify: `workers/config_mgmt/tools/__init__.py`
- Modify: `workers/config_mgmt/concurrency.py`
- Modify: `workers/config_mgmt/pipeline.py`
- Modify: `shared/lib_webbh/playbooks.py`
- Modify: `dashboard/src/lib/worker-stages.ts`

All five edits form one atomic coherence commit — they must land together or the three layers drift.

- [ ] **Step 3.1: Export FilePermissionTester from tools package**

In `workers/config_mgmt/tools/__init__.py`, add the import after `HstsTester` and add to `__all__`:

Replace:
```python
from .hsts_tester import HstsTester
from .rpc_tester import RpcTester
```

With:
```python
from .hsts_tester import HstsTester
from .rpc_tester import RpcTester
from .file_permission_tester import FilePermissionTester
```

And in `__all__`, add `"FilePermissionTester"` after `"HstsTester"`:

Replace:
```python
    "HstsTester",
    "RpcTester",
```

With:
```python
    "HstsTester",
    "RpcTester",
    "FilePermissionTester",
```

- [ ] **Step 3.2: Register weight class in concurrency.py**

In `workers/config_mgmt/concurrency.py`, add the entry after `"hsts_tester"`:

Replace:
```python
    "hsts_tester":                WeightClass.LIGHT,
    "rpc_tester":                 WeightClass.LIGHT,
```

With:
```python
    "hsts_tester":                WeightClass.LIGHT,
    "rpc_tester":                 WeightClass.LIGHT,
    "file_permission_tester":     WeightClass.LIGHT,
```

- [ ] **Step 3.3: Add file_permission stage to pipeline.py**

In `workers/config_mgmt/pipeline.py`, add `FilePermissionTester` to the import and insert the new stage after `rpc_testing`.

Replace the import block:
```python
from workers.config_mgmt.tools import (
    NetworkConfigTester,
    AdminInterfaceFinder,
    DefaultCredentialTester,
    PlatformFingerprinter,
    FileExtensionTester,
    BackupFileFinder,
    FfufTool,
    AdminInterfaceEnumerator,
    AdminParamTamperer,
    ApiDiscoveryTool,
    HttpMethodTester,
    HstsTester,
    RpcTester,
    FileInclusionTester,
    SubdomainTakeoverChecker,
    CloudStorageAuditor,
)
```

With:
```python
from workers.config_mgmt.tools import (
    NetworkConfigTester,
    AdminInterfaceFinder,
    DefaultCredentialTester,
    PlatformFingerprinter,
    FileExtensionTester,
    BackupFileFinder,
    FfufTool,
    AdminInterfaceEnumerator,
    AdminParamTamperer,
    ApiDiscoveryTool,
    HttpMethodTester,
    HstsTester,
    RpcTester,
    FilePermissionTester,
    FileInclusionTester,
    SubdomainTakeoverChecker,
    CloudStorageAuditor,
)
```

Replace the STAGES list entries for `rpc_testing` and `file_inclusion`:
```python
    Stage("rpc_testing", [RpcTester]),
    Stage("file_inclusion", [FileInclusionTester]),
```

With:
```python
    Stage("rpc_testing",      [RpcTester]),
    Stage("file_permission",  [FilePermissionTester]),
    Stage("file_inclusion",   [FileInclusionTester]),
```

- [ ] **Step 3.4: Add file_permission to playbooks.py**

In `shared/lib_webbh/playbooks.py`, the `config_mgmt` stage list currently reads:

```python
    "config_mgmt": [
        "network_config", "network_config_cred_test", "platform_config", "file_extension_handling",
        "backup_files", "admin_interface_enumeration", "api_discovery", "http_methods", "hsts_testing",
        "rpc_testing", "file_inclusion", "subdomain_takeover", "cloud_storage",
    ],
```

Replace it with:
```python
    "config_mgmt": [
        "network_config", "network_config_cred_test", "platform_config", "file_extension_handling",
        "backup_files", "admin_interface_enumeration", "api_discovery", "http_methods", "hsts_testing",
        "rpc_testing", "file_permission", "file_inclusion", "subdomain_takeover", "cloud_storage",
    ],
```

- [ ] **Step 3.5: Update worker-stages.ts**

In `dashboard/src/lib/worker-stages.ts`, replace lines 34–36 (the `file_inclusion` through `cloud_storage` entries under `config_mgmt`):

Replace:
```typescript
    { id: "10", name: "File Inclusion",                 stageName: "file_inclusion",                sectionId: "WSTG-CONF-09" },
    { id: "11", name: "Subdomain Takeover",             stageName: "subdomain_takeover",            sectionId: "WSTG-CONF-10" },
    { id: "12", name: "Cloud Storage",                  stageName: "cloud_storage",                 sectionId: "WSTG-CONF-11" },
```

With:
```typescript
    { id: "10", name: "File Permission",                stageName: "file_permission",               sectionId: "WSTG-CONF-09" },
    { id: "11", name: "File Inclusion",                 stageName: "file_inclusion",                sectionId: "WSTG-INPV-11" },
    { id: "12", name: "Subdomain Takeover",             stageName: "subdomain_takeover",            sectionId: "WSTG-CONF-10" },
    { id: "13", name: "Cloud Storage",                  stageName: "cloud_storage",                 sectionId: "WSTG-CONF-11" },
```

- [ ] **Step 3.6: Verify all existing unit tests still pass**

```bash
pytest tests/unit/config_mgmt/ -v
```

Expected: All tests pass (existing tests for hsts_tester, http_method_tester, network_config_tester, etc. must remain green).

- [ ] **Step 3.7: Commit the three-layer coherence update**

```bash
git add workers/config_mgmt/tools/__init__.py \
        workers/config_mgmt/concurrency.py \
        workers/config_mgmt/pipeline.py \
        shared/lib_webbh/playbooks.py \
        dashboard/src/lib/worker-stages.ts
git commit -m "feat(conf09): wire file_permission stage across pipeline, playbooks, and dashboard"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task covering it |
|---|---|
| New `FilePermissionTester` tool — pure async `execute()` | Task 2 |
| Phase 1: directory listing detection (14 paths, listing signatures) | Task 2 step 2.1 |
| Phase 2: sensitive file exposure (25 paths, 4 severity tiers) | Task 2 step 2.1 |
| `section_id = "WSTG-CONF-09"` on all findings | Task 2 (all classifier functions) |
| `follow_redirects=False` on httpx client | Task 2 step 2.1 |
| Cooldown check, semaphore acquire/release lifecycle | Task 2 step 2.1 |
| Scope check before probing | Task 2 step 2.1 |
| `file_permission` stage added to `pipeline.py` after `rpc_testing` | Task 3 step 3.3 |
| `file_permission_tester: WeightClass.LIGHT` in `concurrency.py` | Task 3 step 3.2 |
| `FilePermissionTester` exported from `tools/__init__.py` | Task 3 step 3.1 |
| `file_permission` added to `playbooks.py` `config_mgmt` list | Task 3 step 3.4 |
| `worker-stages.ts` new `file_permission` entry with `sectionId: "WSTG-CONF-09"` | Task 3 step 3.5 |
| `file_inclusion` sectionId fixed to `"WSTG-INPV-11"` | Task 3 step 3.5 |
| 15 pure-function unit tests | Task 1 + Task 2 |

All spec requirements covered. ✓

**Placeholder scan:** No TBDs, no "similar to above", all code blocks are complete. ✓

**Type consistency:**
- `_classify_directory(url, status, body)` — defined Task 2, tested Task 1: consistent ✓
- `_classify_sensitive_file(url, path, status, severity)` — defined Task 2, tested Task 1: consistent ✓
- `_is_directory_listing(body)` — defined Task 2, tested Task 1: consistent ✓
- `FilePermissionTester.name = "file_permission_tester"` matches `TOOL_WEIGHTS` key: consistent ✓
- Stage name `"file_permission"` used identically in pipeline, playbooks, and dashboard: consistent ✓
