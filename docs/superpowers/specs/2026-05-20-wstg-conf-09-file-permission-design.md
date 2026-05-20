# WSTG-CONF-09: Test File Permission — Design Spec

**Date:** 2026-05-20
**Stage:** `file_permission` (new pipeline index 10, inserted after `rpc_testing` / before `file_inclusion`)
**Worker:** `config_mgmt`
**OWASP ref:** WSTG-CONF-09 — Test File Permission
**Tool file:** `workers/config_mgmt/tools/file_permission_tester.py`

---

## Problem Statement

WSTG-CONF-09 (Test File Permission) is not implemented. The `file_inclusion` stage is
currently mislabeled `sectionId: "WSTG-CONF-09"` in `worker-stages.ts`, but that stage
performs LFI/RFI testing (WSTG-INPV-11), which is an unrelated category.

This spec adds the correct CONF-09 implementation: a two-phase async probe that detects
open directory indexes and exposed sensitive files.

---

## Goals

- Add `FilePermissionTester` — pure async `execute()` override, no subprocess
- Phase 1: detect directories with open listing (Apache/Nginx "Index of" style)
- Phase 2: probe a curated list of always-restricted sensitive paths for HTTP 200 responses
- Set `section_id = "WSTG-CONF-09"` on every finding
- Add `file_permission` as a new 14th pipeline stage (index 13)
- Fix `file_inclusion` sectionId in `worker-stages.ts` from `"WSTG-CONF-09"` → `"WSTG-INPV-11"`
- Add pure-function unit tests covering all classification logic

---

## Architecture

```
file_permission stage (pipeline index 10 — new, after rpc_testing, before file_inclusion)
  └── FilePermissionTester.execute()
        ├── Phase 0 — Base URL resolution + scope check
        │     ├── Parse target_value → base_url
        │     └── scope_manager.is_in_scope() → early return if out of scope
        ├── Phase 1 — Directory listing detection (asyncio.Semaphore(10))
        │     Per directory path (~14 paths):
        │     ├── GET {base_url}/{dir}/
        │     ├── 200 + listing signature in body → high vulnerability
        │     ├── 403 → observation (directory exists, access-controlled)
        │     └── other status codes → skip
        └── Phase 2 — Sensitive file exposure (asyncio.Semaphore(10))
              Per sensitive path (~25 paths):
              ├── GET {base_url}/{sensitive_path}
              ├── 200 → severity based on file category (critical/high/medium/low)
              └── non-200 → skip (protected or absent)
```

---

## Module-Level Pure Functions

Extracted at module level for unit testability without DB, network, or async runtime:

```python
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
    # (path, severity)
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

def _classify_directory(url: str, status: int, body: str) -> dict | None:
    """Return a vuln or observation dict for a directory probe result, or None to skip."""

def _classify_sensitive_file(url: str, path: str, status: int, severity: str) -> dict | None:
    """Return a vuln dict if status is 200, else None."""
```

---

## Severity Classification

### Phase 1 — Directory listing

| Condition | Severity | Type |
|---|---|---|
| 200 + listing signature in body | `high` | vulnerability — `"Directory listing enabled at {url}"` |
| 403 | — | observation — `directory_access / access_denied` |
| other | — | skip |

### Phase 2 — Sensitive file exposure

| File category | Severity | Condition |
|---|---|---|
| `.env*`, `.git/config`, `.htpasswd`, `config.php`, `wp-config.php`, `database.php`, `.ssh/id_rsa` | `critical` | HTTP 200 |
| `web.config`, `WEB-INF/web.xml`, `WEB-INF/web.properties`, `.git/HEAD`, `.svn/entries`, `docker-compose.yml`, `settings.php`, `.bash_history` | `high` | HTTP 200 |
| `.htaccess`, `server-status`, `server-info`, `phpinfo.php`, `Dockerfile` | `medium` | HTTP 200 |
| `.DS_Store`, `composer.json`, `package.json` | `low` | HTTP 200 |

All vulnerability rows: `section_id = "WSTG-CONF-09"`, `worker_type = "config_mgmt"`.

---

## Async Probe Coroutines

```python
async def _probe_directory(
    client: httpx.AsyncClient,
    base_url: str,
    dir_path: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    """GET {base_url}/{dir_path}/ and classify the response."""

async def _probe_sensitive_file(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    severity: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    """GET {base_url}/{path} and classify the response."""
```

Both are module-level so they can be tested directly without instantiating the tool class.

---

## HTTP Client Config

```python
httpx.AsyncClient(
    verify=False,
    follow_redirects=False,
    timeout=10,
    headers=headers or {},
)
```

`follow_redirects=False` — a redirect away from a sensitive file may itself be a finding
(e.g., redirect to a login page implies the file exists). Per-request `httpx.RequestError`
is silently swallowed (unreachable host is not a vulnerability).

---

## Lifecycle (execute override)

```
execute(target, scope_manager, target_id, container_name, headers)
 ├─ check_cooldown()                    → early return if within cooldown
 ├─ acquire semaphore (LIGHT)
 ├─ emit TOOL_PROGRESS: started
 │
 ├─ resolve base_url from target_value
 ├─ scope-check base_url               → early return if out of scope
 │
 ├─ Phase 1 — directory listing
 │   asyncio.Semaphore(10) inner
 │   per dir_path: GET {base_url}/{dir_path}/
 │   _classify_directory() → collect results
 │
 ├─ Phase 2 — sensitive file exposure
 │   asyncio.Semaphore(10) inner
 │   per (path, severity): GET {base_url}/{path}
 │   _classify_sensitive_file() → collect results
 │
 ├─ persist all results via _process_result()
 ├─ update job_state.last_tool_executed
 ├─ emit TOOL_PROGRESS: finished
 └─ return {found, in_scope, new, skipped_cooldown}
```

---

## Three-Layer Changes

| Layer | File | Change |
|---|---|---|
| Execution | `workers/config_mgmt/tools/file_permission_tester.py` | New file — `FilePermissionTester` class |
| Execution | `workers/config_mgmt/tools/__init__.py` | Add `FilePermissionTester` import + `__all__` entry |
| Execution | `workers/config_mgmt/pipeline.py` | Import `FilePermissionTester`; add `Stage("file_permission", [FilePermissionTester])` at index 10 (after `rpc_testing`, before `file_inclusion`) |
| Execution | `workers/config_mgmt/concurrency.py` | Add `"file_permission_tester": WeightClass.LIGHT` to `TOOL_WEIGHTS` |
| Enablement | `shared/lib_webbh/playbooks.py` | Add `"file_permission"` to `PIPELINE_STAGES["config_mgmt"]` list |
| Display | `dashboard/src/lib/worker-stages.ts` | Add `file_permission` entry with `sectionId: "WSTG-CONF-09"`; change `file_inclusion` sectionId from `"WSTG-CONF-09"` → `"WSTG-INPV-11"` |

---

## Unit Tests

File: `tests/unit/config_mgmt/test_file_permission_tester.py`

All pure-function — no DB, no network, no async runtime required.

| Test | Assertion |
|---|---|
| `test_is_directory_listing_index_of` | Body with "Index of /tmp" → True |
| `test_is_directory_listing_parent_dir` | Body with "Parent Directory" → True |
| `test_is_directory_listing_false` | Normal HTML body → False |
| `test_classify_directory_listing_high` | status=200, listing body → high vuln |
| `test_classify_directory_403` | status=403 → observation `directory_access / access_denied` |
| `test_classify_directory_404` | status=404 → None |
| `test_classify_sensitive_file_200_critical` | `.env`, 200 → critical vuln |
| `test_classify_sensitive_file_200_high` | `web.config`, 200 → high vuln |
| `test_classify_sensitive_file_200_medium` | `phpinfo.php`, 200 → medium vuln |
| `test_classify_sensitive_file_200_low` | `composer.json`, 200 → low vuln |
| `test_classify_sensitive_file_non_200` | `.env`, 404 → None |
| `test_section_id_in_directory_vuln` | directory listing vuln → `section_id == "WSTG-CONF-09"` |
| `test_section_id_in_file_vuln` | sensitive file vuln → `section_id == "WSTG-CONF-09"` |
| `test_section_id_constant` | `_SECTION_ID == "WSTG-CONF-09"` |

---

## Out of Scope

- Adding or renaming existing pipeline stages other than appending `file_permission`
- Rewriting `FileInclusionTester` (LFI/RFI — separate WSTG-INPV-11 work)
- Upload directory write-access testing (PUT/POST probes)
- DB-driven path composition using previously discovered assets
- Changes to any worker other than `config_mgmt`
