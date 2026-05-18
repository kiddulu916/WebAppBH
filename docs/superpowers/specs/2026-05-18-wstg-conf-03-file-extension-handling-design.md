# WSTG-CONF-03: File Extension Handling — Design Spec

**Date:** 2026-05-18
**Stage:** `file_extension_handling` (pipeline index 3)
**Worker:** `config_mgmt`
**OWASP ref:** WSTG-CONF-03 — Test File Extensions Handling for Sensitive Information
**Tool file:** `workers/config_mgmt/tools/file_extension_tester.py`

---

## Objective

Rewrite `FileExtensionTester` to fully implement WSTG-CONF-03. The current tool tests only 3 hard-coded path stems, uses a subprocess inline script, and carries the wrong `section_id`. The rewrite must:

- Query the DB for paths discovered in prior stages and use them as test targets
- Conditionally run Windows 8.3 short-filename bypass tests when IIS is detected
- Detect source code disclosure, credential leakage, and never-serve extension exposure
- Classify findings with correct severity and `section_id = "WSTG-CONF-03"`

No changes are required to `pipeline.py`, `playbooks.py`, `dashboard/worker-stages.ts`, or `concurrency.py` — the stage slot and tool registration already exist.

---

## Architecture

`FileExtensionTester` overrides `execute()` entirely. `build_command()` and `parse_output()` are implemented as stubs that raise `NotImplementedError` — they satisfy the ABC contract but are never called.

The overridden `execute()` replicates the base lifecycle then performs three phases:

```
execute(target, scope_manager, target_id, container_name, headers)
 ├─ check_cooldown()                    → early return if within cooldown
 ├─ acquire_semaphore (global)
 ├─ emit TOOL_PROGRESS: started
 │
 ├─ [Phase 1 — DB Query]
 │   ├─ SELECT asset_value WHERE asset_type IN ('url','page','endpoint')
 │   │   → extract path stems via urllib.parse
 │   └─ SELECT 1 WHERE asset_type = 'server_software' AND value ILIKE '%IIS%'
 │       → iis_detected: bool
 │
 ├─ [Phase 2 — Build Test Matrix]
 │   ├─ path_stems = DB-derived stems ∪ CURATED_FALLBACK_STEMS
 │   └─ test_pairs = cartesian(path_stems × EXTENSION_CATEGORIES)
 │       + Windows 8.3 pairs if iis_detected
 │
 ├─ [Phase 3 — HTTP Testing]
 │   ├─ asyncio.gather over all test_pairs
 │   ├─ inner asyncio.Semaphore(20) caps concurrent requests
 │   └─ each pair → GET → analyze_response() → finding dict or None
 │
 ├─ [Phase 4 — Persist]
 │   └─ _process_vulnerability() or _process_observation() per finding
 │
 ├─ update job_state.last_tool_executed
 ├─ emit TOOL_PROGRESS: finished
 └─ return {found, in_scope, new, skipped_cooldown}
```

---

## Test Coverage

### Extension Categories

| Category | Extensions | Finding trigger |
|---|---|---|
| Never-serve | `.asa`, `.inc`, `.config` | HTTP 200 — always a vuln |
| Source code | `.php`, `.php3`, `.php4`, `.php5`, `.phtml`, `.phps`, `.asp`, `.aspx`, `.jsp`, `.jspx`, `.rb`, `.py`, `.pl`, `.cgi` | HTTP 200 + raw template syntax in body OR `Content-Type: text/plain` |
| Configuration | `.xml`, `.yml`, `.yaml`, `.ini`, `.conf`, `.cfg`, `.properties`, `.env`, `.toml` | HTTP 200 |
| Backup/legacy | `.bak`, `.old`, `.orig`, `.swp`, `.tmp`, `~`, `.backup`, `.save` | HTTP 200 |
| Archives | `.zip`, `.tar`, `.gz`, `.tgz`, `.rar`, `.7z` | HTTP 200 |
| Database | `.sql`, `.db`, `.sqlite`, `.sqlite3`, `.mdb` | HTTP 200 — always critical |
| Documents/logs | `.txt`, `.log` | HTTP 200 + credential pattern match only |

### Source Code Disclosure Detection

`analyze_response()` checks for raw template syntax in the response body:
- PHP: `<?php`, `<?=`
- ASP/ASPX: `<%`, `<%@`, `Response.Write`
- JSP: `<jsp:`, `<%@page`
- Ruby ERB: `<%=`
- Python template: `{% %}`, `{{ }}`

Also checks `Content-Type` header: `text/plain` or `application/octet-stream` for a source extension confirms source code is served rather than executed.

### Windows 8.3 Bypass (IIS only)

When `iis_detected = True`, for each DB-derived path stem generate the 8.3 short-name equivalent (first 6 chars uppercased + `~1`) and test with `.PHP`, `.PHT`, `.ASP` suffixes. A finding is recorded when the 8.3 URL returns HTTP 200 while the canonical path does not.

### Credential Pattern Detection

Applied to all response bodies regardless of category. Patterns (case-insensitive):
`password`, `passwd`, `api_key`, `apikey`, `secret`, `token`, `db_pass`, `database_url`, `mysql://`, `postgres://`, `connection_string`, `private_key`

### Path Stem Sources

**DB-derived:** `Asset.asset_value` where `asset_type IN ('url', 'page', 'endpoint')` — path component extracted via `urllib.parse.urlparse(value).path`, extension stripped via `os.path.splitext`.

**Curated fallback** (always included, merged with DB set):
`/index`, `/default`, `/config`, `/configuration`, `/database`, `/db`, `/app`, `/application`, `/admin`, `/login`, `/settings`, `/setup`, `/install`, `/backup`, `/data`, `/api`, `/web`

---

## Severity Classification

| Condition | Severity |
|---|---|
| Any accessible file + credential match in body | `critical` |
| Database file accessible (`.sql`, `.db`, etc.) | `critical` |
| Source code returned raw | `high` |
| Never-serve extension accessible (`.asa`, `.inc`, `.config`) | `high` |
| Windows 8.3 bypass confirmed | `high` |
| Archive file accessible | `high` |
| Config/backup/legacy file accessible | `medium` |
| Document/log accessible (no credential match) | skipped |

---

## Data Flow

### DB Reads

```sql
-- Path stems from prior stage discoveries
SELECT asset_value FROM assets
WHERE target_id = :tid
AND asset_type IN ('url', 'page', 'endpoint');

-- IIS detection from platform_config stage
SELECT 1 FROM assets
WHERE target_id = :tid
AND asset_type = 'server_software'
AND asset_value ILIKE '%IIS%'
LIMIT 1;
```

Both queries run before any HTTP work. If DB is empty, the curated fallbacks cover the test surface.

### HTTP Client

- `httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10)`
- `follow_redirects=False` — a redirect on a `.bak` file is itself informational; the 200 after redirect on a source file is the real signal. Both cases are captured.
- Per-request `httpx.RequestError` and `asyncio.TimeoutError` are silently swallowed — one unreachable path does not abort the matrix.

### DB Writes

- Vulnerabilities via `_process_vulnerability()` — deduplication by `(target_id, title)` is handled in the base class
- `section_id = "WSTG-CONF-03"` on every vulnerability row
- `worker_type = "config_mgmt"`
- Windows 8.3 bypass observations via `_process_observation()` with `asset_type = "win83_bypass"`

### Stats

Standard `{found, in_scope, new, skipped_cooldown}` dict — no changes to pipeline aggregation.

---

## Files Changed

| File | Change |
|---|---|
| `workers/config_mgmt/tools/file_extension_tester.py` | Full rewrite |

No other files require changes.
