# WSTG-CONF-12: Test for Content Security Policy

**Date:** 2026-05-21
**Worker:** `config_mgmt`
**Section ID:** `WSTG-CONF-12`
**Reference:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy

---

## Overview

Add a `CspTester` tool to the `config_mgmt` worker implementing full WSTG-CONF-12 coverage:

1. HTTP header presence and directive quality analysis
2. Meta-tag CSP detection and classification
3. Google CSP Evaluator API augmentation
4. cspbypass CLI bypass-technique detection

The tool is a new 15th pipeline stage (`csp_testing`) appended after `cloud_storage`. All three coherence-layer files update in the same commit.

---

## Architecture

### New file

`workers/config_mgmt/tools/csp_tester.py`

Class `CspTester(ConfigMgmtTool)` — overrides `execute()` directly (same pattern as `HstsTester`). `build_command` and `parse_output` raise `NotImplementedError`.

### Module-level pure helpers (unit-testable without I/O)

| Function | Purpose |
|---|---|
| `_parse_csp_header(header: str) -> dict` | Tokenizes a CSP string into `{directive: [sources]}` |
| `_classify_directives(host: str, url: str, policy: dict) -> list[dict]` | Returns vuln/observation dicts for every weakness in the policy |
| `_scan_meta_tag(host: str, url: str, html: str) -> list[dict]` | Parses HTML body for `<meta http-equiv="Content-Security-Policy">` and returns findings |

### Async helpers (called from `execute()`)

| Function | Purpose |
|---|---|
| `_probe_url(client, url, sem) -> tuple[headers, html]` | Single GET capturing response headers and body |
| `_call_google_csp_evaluator(policy_str: str) -> list[dict]` | POST to Google CSP Evaluator API, map findings to vuln dicts |
| `_run_csp_bypass(url: str) -> list[dict]` | Invoke `cspbypass` subprocess, parse bypass technique output |

### Three-layer coherence changes

| File | Change |
|---|---|
| `workers/config_mgmt/pipeline.py` | Append `Stage("csp_testing", [CspTester])` |
| `shared/lib_webbh/playbooks.py` | Append `"csp_testing"` to `config_mgmt` stage list |
| `dashboard/src/lib/worker-stages.ts` | Append `{ id: "14", name: "Content Security Policy", stageName: "csp_testing", sectionId: "WSTG-CONF-12" }` |

### Concurrency

Add `"csp_tester": WeightClass.LIGHT` to `TOOL_WEIGHTS` in `workers/config_mgmt/concurrency.py`.

---

## Data Flow

`CspTester.execute()` phases:

1. **Cooldown check** — return early if within `COOLDOWN_HOURS`
2. **Semaphore acquire** — `WeightClass.LIGHT`
3. **Collect probe targets** — query `asset_type IN ('domain', 'subdomain', 'url', 'endpoint')` for `target_id`; scope-filter each; fall back to `target.target_value` if DB empty (treated as a URL, `https://` prepended if no scheme present)
4. **Concurrent probing** — `asyncio.Semaphore(10)` inner semaphore; one `httpx.AsyncClient.get()` per URL capturing headers + body in one round-trip
5. **Per-response analysis** (for each successful response):
   - Layer 1: `_classify_directives` on HTTP header value
   - Layer 2: `_call_google_csp_evaluator` (awaited, non-fatal on error)
   - Layer 3: `_run_csp_bypass` subprocess on the URL (non-fatal on missing binary)
   - `_scan_meta_tag` on response body HTML
6. **Persist** — `_process_result` for each finding dict
7. **`job_state` update** + `TOOL_PROGRESS` events (0% start, 100% finish)

---

## Directive Classification Rules (Layer 1)

| Condition | Severity | Finding name |
|---|---|---|
| No CSP header and no meta tag | `high` | `Missing CSP on {url}` |
| `unsafe-inline` in `script-src` / `default-src` | `high` | `CSP allows unsafe-inline scripts on {host}` |
| `unsafe-eval` in `script-src` / `default-src` | `high` | `CSP allows unsafe-eval on {host}` |
| `*` wildcard in `script-src` / `default-src` | `high` | `CSP wildcard script source on {host}` |
| `http:` or `data:` as script source scheme | `high` | `CSP allows insecure script source scheme on {host}` |
| `*` wildcard in `style-src` | `medium` | `CSP wildcard style source on {host}` |
| `unsafe-inline` in `style-src` | `medium` | `CSP allows unsafe-inline styles on {host}` |
| Missing `default-src` | `medium` | `CSP missing default-src on {host}` |
| Missing `object-src` (not covered by `default-src`) | `medium` | `CSP missing object-src on {host}` |
| `*` wildcard in `img-src` / `font-src` | `low` | `CSP wildcard media source on {host}` |
| CSP via meta tag instead of HTTP header | `low` | `CSP delivered via meta tag on {host}` |
| No issues found | `observation` | type `csp_config`, value `"compliant"` |

Each finding carries `location` (probed URL) and `section_id = "WSTG-CONF-12"`.

---

## Google CSP Evaluator Integration (Layer 2)

- **Endpoint:** `POST https://csp-evaluator.withgoogle.com/getCSPEvaluation`
- **Input:** `{"csp": "<policy string>"}`
- **Output:** `findings[]` array with `severity` and `description` per finding
- **Mapping:** Google severity levels → framework `high`/`medium`/`low`/`info`
- **Failure handling:** timeout or 5xx → log warning, return empty list (non-fatal)

---

## cspbypass Integration (Layer 3)

- **Invocation:** subprocess `cspbypass <url>` per probe URL
- **Output:** bypass techniques found (JSONP endpoint abuse, Angular/jQuery CDN bypasses, open-redirect chains on whitelisted domains)
- **Mapping:** each confirmed bypass → `high` vulnerability
- **Failure handling:**
  - `FileNotFoundError` → log error once, skip Layer 3 for all URLs
  - Subprocess timeout → log warning, skip Layer 3 for that URL

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| Single URL probe failure (`httpx.RequestError`) | Skip URL, continue |
| Google API timeout / 5xx | Log warning, skip Layer 2 for that URL |
| `cspbypass` binary missing | Log error once, skip Layer 3 for all URLs |
| `cspbypass` subprocess timeout | Log warning, skip Layer 3 for that URL |
| Malformed / unparseable CSP header | Emit `observation` with `type="csp_parse_error"` |

Duplicate findings (same title, same target) are suppressed by the existing `_process_vulnerability` uniqueness check.

---

## Testing

### Unit tests — `tests/unit/test_csp_tester.py`

Tests cover pure helper functions only (no network, no DB):

| Test | Asserts |
|---|---|
| `test_parse_csp_header` | Correct tokenization; handles quoted strings and semicolons |
| `test_classify_directives_missing_csp` | Empty policy → one `high` vuln |
| `test_classify_directives_unsafe_inline_script` | `unsafe-inline` in `script-src` → `high` |
| `test_classify_directives_unsafe_eval` | `unsafe-eval` → `high` |
| `test_classify_directives_wildcard_script` | `*` in `script-src` → `high` |
| `test_classify_directives_http_scheme` | `http:` in `script-src` → `high` |
| `test_classify_directives_missing_default_src` | Medium vuln, not high |
| `test_classify_directives_compliant` | Strict policy → `observation` only, no vulns |
| `test_scan_meta_tag_present` | HTML with meta CSP → `low` vuln + directive findings |
| `test_scan_meta_tag_absent` | Clean HTML → empty list |

### E2E update — `tests/e2e/test_config_mgmt.py`

- Update `LAST_STAGE` to `"csp_testing"`
- Add `"csp_testing": None` to `STAGE_ASSERTIONS` (presence check; Google API and cspbypass not assumed available in CI)
