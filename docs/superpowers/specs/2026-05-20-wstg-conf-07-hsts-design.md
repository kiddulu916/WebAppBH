# WSTG-CONF-07: HTTP Strict Transport Security — Design Spec

**Date:** 2026-05-20
**Stage:** `hsts_testing` (pipeline index 8, already wired)
**Worker:** `config_mgmt`
**OWASP ref:** WSTG-CONF-07 — Test HTTP Strict Transport Security
**Tool file:** `workers/config_mgmt/tools/hsts_tester.py`

---

## Problem Statement

The existing `HstsTester` uses the old `build_command` + `parse_output` subprocess anti-pattern
(`build_command` spawns `["python3", "-c", script]`). This was the pre-CONF-04 style. Problems:

- All probe logic runs in a subprocess; can't share the async DB session or httpx client
- Vulnerabilities don't set `section_id` — `base_tool._process_vulnerability` defaults to `"WSTG-CONF-01"`
- No scope check before probing URLs
- No DB-driven host discovery — only probes the base target URL, ignoring discovered subdomains
- No HTTP→HTTPS redirect verification (critical for WSTG-CONF-07)
- No detection of HSTS header on HTTP responses (RFC 6797 §8.1 violation)
- No unit tests

The three-layer sync (`pipeline.py` / `playbooks.py` / `worker-stages.ts`) is already correct
and requires no changes.

---

## Goals

- Rewrite `HstsTester` to override `execute()` directly — pure async httpx, no subprocess
- Set `section_id = "WSTG-CONF-07"` on every finding
- Scope-check the base URL and every discovered host before probing
- Read discovered `domain` / `subdomain` assets from the DB (from prior stages)
- Implement full WSTG-CONF-07 methodology: HSTS header quality + HTTP redirect behavior
- Add pure-function unit tests covering all classification logic

---

## Architecture

```
hsts_testing stage (pipeline index 8 — no wiring changes)
  └── HstsTester.execute()
        ├── Phase 0 — Host collection
        │     ├── DB read: asset_type IN ('domain', 'subdomain')
        │     │   scope-check each → keep only in-scope hosts
        │     └── Fallback: base target URL if DB empty or all out-of-scope
        ├── Phase 1 — HTTPS probe (asyncio.Semaphore(10))
        │     Per host:
        │     ├── GET https://{host}/ — inspect Strict-Transport-Security
        │     ├── Missing header → medium vulnerability
        │     ├── max-age < 31536000 → low vulnerability
        │     ├── max-age OK, no includeSubDomains → low vulnerability
        │     ├── preload absent → observation (informational, not a vuln)
        │     └── All checks pass → observation (hsts_config / compliant)
        └── Phase 2 — HTTP redirect probe (asyncio.Semaphore(10))
              Per host:
              ├── GET http://{host}/ (follow_redirects=False)
              ├── No redirect (200 on HTTP) → high vulnerability
              ├── Redirects to HTTP URL (not HTTPS) → high vulnerability
              ├── HSTS header present on HTTP response → low vulnerability
              │   (RFC 6797 §8.1: must be ignored on HTTP — server misconfiguration)
              └── Redirects to HTTPS → observation (http_redirect / to_https)
```

---

## Module-Level Pure Functions

The following functions are extracted at module level so they can be unit-tested without DB or network:

```python
_SECTION_ID = "WSTG-CONF-07"

def _parse_hsts_header(header: str) -> dict:
    """Parse STS header into {max_age, include_subdomains, preload}."""

def _classify_hsts(host: str, header: str) -> list[dict]:
    """Return list of vuln/observation dicts for a given HSTS header value."""

def _classify_http_redirect(host: str, status: int, location: str | None) -> dict:
    """Return vuln/observation dict based on HTTP response status + Location."""

def _hsts_on_http(host: str, header: str) -> dict | None:
    """Return low vuln if HSTS header appears on HTTP response, else None."""
```

---

## Severity Classification

### Phase 1 — HTTPS HSTS header quality

| Condition | Severity | Type |
|---|---|---|
| No `Strict-Transport-Security` header | `medium` | vulnerability — `"Missing HSTS header on {host}"` |
| `max-age` < 31536000 | `low` | vulnerability — `"HSTS max-age too short on {host}"` |
| `max-age` OK, no `includeSubDomains` | `low` | vulnerability — `"HSTS missing includeSubDomains on {host}"` |
| No `preload` directive | — | observation — `hsts_config / no_preload` |
| All directives OK | — | observation — `hsts_config / compliant` |

### Phase 2 — HTTP redirect behavior

| Condition | Severity | Type |
|---|---|---|
| HTTP 200 (no redirect) | `high` | vulnerability — `"HTTP not redirected to HTTPS on {host}"` |
| HTTP redirects to non-HTTPS URL | `high` | vulnerability — `"HTTP redirects to non-HTTPS URL on {host}"` |
| HSTS header on HTTP response | `low` | vulnerability — `"HSTS header on plain HTTP response on {host}"` |
| HTTP redirects to HTTPS | — | observation — `http_redirect / to_https` |

All vulnerability rows: `section_id = "WSTG-CONF-07"`, `worker_type = "config_mgmt"`.

---

## Phase 0: Host Collection Detail

```python
DB_ASSET_TYPES = ["domain", "subdomain"]
```

Query:
```sql
SELECT asset_value FROM assets
WHERE target_id = :tid AND asset_type IN ('domain', 'subdomain')
```

After fetching, scope-check each host: skip any where `scope_manager.is_in_scope(host).in_scope`
is False. If the filtered list is empty, fall back to the base target URL (scope-checked).

---

## HTTP Client Config

```python
httpx.AsyncClient(
    verify=False,
    follow_redirects=False,
    timeout=10,
)
```

`follow_redirects=False` — redirect destination is the key data point in Phase 2; following
it would hide the vulnerability. Per-request `httpx.RequestError` is silently swallowed
(network errors mean the host is unreachable, not vulnerable).

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
 ├─ Phase 0 — collect hosts (DB + fallback)
 │
 ├─ Phase 1 — HTTPS probe
 │   asyncio.Semaphore(10) inner
 │   per host: GET https://{host}/, inspect STS header
 │   _classify_hsts() → _process_result()
 │
 ├─ Phase 2 — HTTP redirect probe
 │   asyncio.Semaphore(10) inner
 │   per host: GET http://{host}/
 │   _classify_http_redirect() + _hsts_on_http() → _process_result()
 │
 ├─ persist all results via _process_result()
 ├─ update job_state.last_tool_executed
 ├─ emit TOOL_PROGRESS: finished
 └─ return {found, in_scope, new, skipped_cooldown}
```

---

## Unit Tests

File: `tests/unit/config_mgmt/test_hsts_tester.py`

All tests are pure-function — no DB, no network, no async runtime required.

| Test | Assertion |
|---|---|
| `test_parse_hsts_header_full` | `max-age=31536000; includeSubDomains; preload` → all fields True/correct |
| `test_parse_hsts_header_max_age_only` | only `max-age=3600` → include_subdomains=False, preload=False |
| `test_classify_hsts_missing_header` | `""` → list contains medium vuln |
| `test_classify_hsts_max_age_too_short` | max-age=3600 → list contains low vuln |
| `test_classify_hsts_missing_include_subdomains` | max-age ok, no includeSubDomains → list contains low vuln |
| `test_classify_hsts_no_preload` | max-age ok, includeSubDomains, no preload → observation only (no vuln) |
| `test_classify_hsts_compliant` | full header → observation compliant, no vulns |
| `test_classify_hsts_section_id` | any vuln from classify has `section_id == "WSTG-CONF-07"` |
| `test_classify_http_redirect_200_is_high` | status=200, location=None → high vuln |
| `test_classify_http_redirect_to_http_is_high` | 301, location=`http://...` → high vuln |
| `test_classify_http_redirect_to_https_is_observation` | 301, location=`https://...` → observation |
| `test_classify_http_redirect_section_id` | vuln from redirect has `section_id == "WSTG-CONF-07"` |
| `test_hsts_on_http_present_is_low` | non-empty header on HTTP → low vuln |
| `test_hsts_on_http_absent_is_none` | empty header → None |
| `test_section_id_constant` | `_SECTION_ID == "WSTG-CONF-07"` |

---

## Files Changed

| File | Change |
|---|---|
| `workers/config_mgmt/tools/hsts_tester.py` | Full rewrite — pure async `execute()`, no subprocess |
| `tests/unit/config_mgmt/test_hsts_tester.py` | New — 15 pure-function unit tests |

**No changes to:** `pipeline.py`, `playbooks.py`, `worker-stages.ts`, `concurrency.py`,
`tools/__init__.py`, or any other worker.

---

## Out of Scope

- Adding or renaming pipeline stages (the `hsts_testing` slot is already wired)
- Mixed-content detection (HTTPS page loading HTTP sub-resources)
- Full HSTS preload list submission verification
- Checking HSTS on individual URL paths (HSTS is a domain-level header)
- Changes to any worker other than `config_mgmt`
