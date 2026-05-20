# WSTG-CONF-06: HTTP Methods — Design Spec

**Date:** 2026-05-20
**Stage:** `http_methods` (pipeline index 7, already wired)
**Worker:** `config_mgmt`
**OWASP ref:** WSTG-CONF-06 — Test HTTP Methods
**Tool file:** `workers/config_mgmt/tools/http_method_tester.py`

---

## Problem Statement

The existing `HttpMethodTester` is a placeholder that uses the old inline-Python subprocess anti-pattern (`build_command` spawns `["python3", "-c", script]`). This was the pre-CONF-04 style. Problems:

- All probe logic runs in a subprocess; can't share the async DB session or httpx client
- Vulnerabilities don't set `section_id` — base_tool's `_process_vulnerability` defaults to `"WSTG-CONF-01"`
- No scope check before probing URLs
- No CORS misconfiguration testing (origin reflection, wildcard + credentials)
- No DB-driven endpoint discovery — only probes hardcoded paths on the base URL
- Missing method override vectors: `X-Method-Override` header and `?_method=` query param
- No unit tests

The three-layer sync (`pipeline.py` / `playbooks.py` / `worker-stages.ts`) is already correct and requires no changes.

---

## Goals

- Rewrite `HttpMethodTester` to override `execute()` directly — pure async httpx, no subprocess
- Set `section_id = "WSTG-CONF-06"` on every finding
- Scope-check every URL before probing
- Read discovered endpoints from the DB (from prior stages)
- Implement full WSTG-CONF-06 methodology: method enumeration, method override, CORS
- Add pure-function unit tests covering severity classification and URL collection

---

## Architecture

```
http_methods stage (pipeline index 7 — no wiring changes)
  └── HttpMethodTester.execute()
        ├── Phase 0 — URL collection
        │     ├── DB read: asset_type IN ('api_endpoint', 'url',
        │     │                'admin_interface', 'backup_file')
        │     │   Filter: scope_manager.is_in_scope(url).in_scope
        │     └── Fallback (if DB empty): base target URL +
        │           ["/", "/api", "/api/v1", "/upload",
        │            "/files", "/static", "/v1", "/v2"]
        ├── Phase 1 — Method enumeration (asyncio.Semaphore(20))
        │     ├── OPTIONS → parse Allow header for dangerous methods
        │     ├── HEAD/TRACE/TRACK → detect XST, method presence
        │     ├── PUT/DELETE/PATCH → 200/201/204 = high vulnerability
        │     ├── COPY/MOVE/MKCOL/LOCK/UNLOCK → 200/201/207 = high
        │     └── PROPFIND on /webdav /dav /remote.php/webdav → 200/207 = high
        ├── Phase 2 — Method override (asyncio.Semaphore(10))
        │     ├── Headers: X-HTTP-Method-Override, X-HTTP-Method,
        │     │             X-Method-Override (each with DELETE)
        │     └── Params:  ?_method=DELETE, ?method=DELETE on base URL
        └── Phase 3 — CORS (asyncio.Semaphore(20))
              ├── Probe each URL with Origin: https://evil.example.com
              ├── ACAO reflects origin → high vulnerability
              ├── ACAO=* + ACAC: true → high vulnerability
              └── ACAC: true alone (no reflection) → medium vulnerability
```

---

## Module-Level Pure Functions

The following functions are extracted at module level so they can be unit-tested without DB or network:

```python
def _classify_method_response(method: str, status: int) -> tuple[str | None, str | None]:
    """Return (severity, description_key) or (None, None)."""

def _classify_cors(origin_sent: str, acao: str, acac: str) -> tuple[str | None, str | None]:
    """Return (severity, vuln_type) for CORS findings, or (None, None) if safe."""

def _is_dangerous_method(method: str) -> bool:
    """True for PUT, DELETE, PATCH, COPY, MOVE, MKCOL, LOCK, UNLOCK, PROPFIND."""

def _build_probe_urls(base_url: str, db_urls: list[str]) -> list[str]:
    """If db_urls non-empty, return them. Otherwise return base_url + fallback paths."""

def _parse_allow_header(allow_str: str) -> list[str]:
    """Split Allow header into normalized uppercase method list."""
```

---

## Severity Classification

### Phase 1 — Method enumeration

| Condition | Severity | Type |
|---|---|---|
| TRACE/TRACK → 200 | `medium` | vulnerability — `"TRACE method enabled (XST)"` |
| OPTIONS Allow contains dangerous method | `medium` | vulnerability — `"Dangerous HTTP method {M} allowed"` |
| PUT/DELETE/PATCH/COPY/MOVE → 200/201/204 | `high` | vulnerability — `"{M} method accepted at {path}"` |
| WebDAV PROPFIND → 200/207 on /webdav paths | `high` | vulnerability — `"WebDAV enabled at {path}"` |
| OPTIONS → 200, no dangerous methods in Allow | — | observation — `http_method_config` / `OPTIONS_enabled` |
| TRACE → 405 | — | observation — `http_method_config` / `TRACE_disabled` |

### Phase 2 — Method override

| Condition | Severity | Type |
|---|---|---|
| GET + `X-HTTP-Method-Override: DELETE` → 200/204 | `high` | vulnerability — `"HTTP method override via X-HTTP-Method-Override"` |
| GET + `X-HTTP-Method: DELETE` → 200/204 | `high` | vulnerability — `"HTTP method override via X-HTTP-Method"` |
| GET + `X-Method-Override: DELETE` → 200/204 | `high` | vulnerability — `"HTTP method override via X-Method-Override"` |
| GET + `?_method=DELETE` → 200/204 | `high` | vulnerability — `"HTTP method override via _method query param"` |
| GET + `?method=DELETE` → 200/204 | `high` | vulnerability — `"HTTP method override via method query param"` |

### Phase 3 — CORS

| Condition | Severity | Type |
|---|---|---|
| ACAO mirrors `https://evil.example.com` | `high` | vulnerability — `"CORS: arbitrary origin reflected at {url}"` |
| ACAO=`*` + ACAC=`true` | `high` | vulnerability — `"CORS: wildcard origin with credentials at {url}"` |
| ACAC=`true`, ACAO not a reflection | `medium` | vulnerability — `"CORS: credentials allowed without strict origin at {url}"` |

All vulnerability rows: `section_id = "WSTG-CONF-06"`, `worker_type = "config_mgmt"`.

---

## Phase 0: URL Collection Detail

```python
PROBE_SUFFIXES = ["/", "/api", "/api/v1", "/upload", "/files", "/static", "/v1", "/v2"]

DB_ASSET_TYPES = ["api_endpoint", "url", "admin_interface", "backup_file"]
```

Query:
```sql
SELECT asset_value FROM assets
WHERE target_id = :tid AND asset_type IN (...DB_ASSET_TYPES...)
```

After fetching, scope-check each URL: skip any where `scope_manager.is_in_scope(url).in_scope` is False. If the filtered list is empty, construct fallback URLs from `base_url + suffix` for each suffix in `PROBE_SUFFIXES` and scope-check those.

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

`follow_redirects=False` — a redirect in response to TRACE or a dangerous method is itself informational. Per-request `httpx.RequestError` is silently swallowed (network errors mean the path is unreachable, not vulnerable).

---

## Lifecycle (execute override)

```
execute(target, scope_manager, target_id, container_name, headers)
 ├─ check_cooldown()                    → early return if within cooldown
 ├─ acquire semaphore (LIGHT)
 ├─ emit TOOL_PROGRESS: started
 │
 ├─ scope-check base target URL        → return early if out of scope
 │
 ├─ Phase 0 — collect URLs (DB + fallback)
 │
 ├─ Phase 1 — method enumeration
 │   asyncio.Semaphore(20) inner
 │   OPTIONS, TRACE, TRACK per URL
 │   PUT/DELETE/PATCH/COPY/MOVE/PROPFIND per URL
 │
 ├─ Phase 2 — method override
 │   asyncio.Semaphore(10) inner
 │   3 headers + 2 query params on base_url only
 │
 ├─ Phase 3 — CORS
 │   asyncio.Semaphore(20) inner
 │   per URL: GET with Origin: https://evil.example.com
 │   inspect ACAO and ACAC response headers
 │
 ├─ persist all results via _process_result()
 ├─ update job_state.last_tool_executed
 ├─ emit TOOL_PROGRESS: finished
 └─ return {found, in_scope, new, skipped_cooldown}
```

---

## Unit Tests

File: `tests/unit/config_mgmt/test_http_method_tester.py`

All tests are pure-function — no DB, no network, no async runtime required.

| Test | Assertion |
|---|---|
| `test_classify_method_response_200_dangerous` | PUT+200 → `("high", ...)` |
| `test_classify_method_response_405` | DELETE+405 → `(None, None)` |
| `test_classify_method_response_trace_200` | TRACE+200 → `("medium", ...)` |
| `test_classify_method_response_403_not_vuln` | PUT+403 → `(None, None)` |
| `test_classify_cors_reflection` | ACAO=evil.example.com → `("high", ...)` |
| `test_classify_cors_wildcard_with_creds` | ACAO=`*`, ACAC=`true` → `("high", ...)` |
| `test_classify_cors_creds_only` | ACAC=`true`, ACAO=something else → `("medium", ...)` |
| `test_classify_cors_safe` | ACAO=`https://same.com`, no ACAC → `(None, None)` |
| `test_is_dangerous_method_true` | PUT, DELETE, PATCH, PROPFIND → True |
| `test_is_dangerous_method_false` | GET, POST, HEAD → False |
| `test_build_probe_urls_uses_db` | db_urls non-empty → returns them unchanged |
| `test_build_probe_urls_fallback` | db_urls=[] → returns base_url+suffixes |
| `test_parse_allow_header_splits_correctly` | `"GET, POST, PUT"` → `["GET", "POST", "PUT"]` |
| `test_parse_allow_header_empty` | `""` → `[]` |
| `test_section_id_in_method_vuln` | vuln dict from classify contains `"WSTG-CONF-06"` |
| `test_section_id_in_cors_vuln` | CORS vuln dict contains `"WSTG-CONF-06"` |

---

## Files Changed

| File | Change |
|---|---|
| `workers/config_mgmt/tools/http_method_tester.py` | Full rewrite — pure async execute(), no subprocess |
| `tests/unit/config_mgmt/test_http_method_tester.py` | New — 16 pure-function unit tests |

**No changes to:** `pipeline.py`, `playbooks.py`, `worker-stages.ts`, `concurrency.py`, `tools/__init__.py`, or any other worker.

---

## Out of Scope

- Adding a new pipeline stage (the `http_methods` slot is already wired)
- Brute-force method fuzzing with arbitrary verb generation
- WebDAV exploitation beyond detection (MKCOL/COPY/MOVE actions)
- Full CORS exploit chain (preflight bypass, credential theft) — detection only
- Changes to any worker other than `config_mgmt`
