# WSTG-ATHN-04: Testing for Bypassing Authentication Schema — Design Spec

**Date:** 2026-06-04
**WSTG reference:** [WSTG-ATHN-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema)
**Worker:** `authentication`
**Stage:** `auth_bypass` (index 2 in STAGES, after `lockout_mechanism`)

---

## 1. Objective

Replace the existing `AuthBypassTester` stub (`workers/authentication/tools/auth_bypass_tester.py`) — which uses the old `build_command`/`parse_output` pattern with an embedded Python subprocess — with a production-quality implementation that:

- Fully probes authentication bypass via forced browsing, parameter modification, HTTP header injection, path traversal, cookie/JWT manipulation, SQL injection on login forms, and session ID prediction
- Prioritizes stealth: configurable delays, User-Agent rotation, IP rotation via `X-Forwarded-For`, and per-URL rate-limit abort logic
- Queries DB-discovered assets (admin interfaces, login URLs) before falling back to a hardcoded path list
- Persists all findings as `Vulnerability` records with `section_id="4.4"`
- Follows the `LockoutTester` architecture from ATHN-03: override `execute()` directly, no subprocess

---

## 2. Architecture

### 2.1 Class structure

`AuthBypassTester(AuthenticationTool)` in `workers/authentication/tools/auth_bypass_tester.py`:

- Overrides `execute()` directly — no `build_command` / `parse_output` (stubs return `["true"]` / `[]`)
- Uses `httpx.AsyncClient` throughout (no subprocess)
- One sync helper and six async helpers:

| Method | Type | Responsibility |
|---|---|---|
| `_load_settings(target_id)` | sync | Reads `rate_limits.json`, `custom_headers.json`, `bypass.json` from `shared/config/{target_id}/` |
| `_discover_targets(base_url, target_id)` | async | Queries `Asset` table for `admin_interface`, `url`, `endpoint` assets; falls back to hardcoded ~30 common protected paths |
| `_discover_login_forms(base_url, target_id)` | async | Queries `Asset` table for `login_url` assets; falls back to probing common login paths (`/login`, `/signin`, `/wp-login.php`, etc.) |
| `_probe_forced_browsing(base_url, paths, settings)` | async | Direct access, param modification, HTTP method override, header injection, path traversal, cookie manipulation, JWT none algorithm |
| `_probe_sqli_bypass(login_urls, settings)` | async | 15-payload SQLi probe on login forms with rate-limiting, User-Agent cycling, IP rotation |
| `_probe_session_prediction(base_url, settings)` | async | Collects 15 session IDs, analyzes entropy, charset diversity, sequential gaps |
| `_save_finding(target_id, ...)` | async | Persists a single `Vulnerability` record |

Abstract stubs required by base class:
```python
def build_command(self, target, credentials=None) -> list[str]:
    return ["true"]  # never called — execute() is overridden

def parse_output(self, stdout: str) -> list:
    return []
```

### 2.2 Execution flow within execute()

```
1. Cooldown check (base class helper)
2. Acquire HEAVY semaphore
3. Emit TOOL_PROGRESS started event

4. _load_settings(target_id)
   shared/config/{target_id}/rate_limits.json      → probe_delay_secs (default 0.3)
   shared/config/{target_id}/custom_headers.json   → extra headers dict
   shared/config/{target_id}/bypass.json           → sqli_delay_secs (default 2.0),
                                                      ip_rotation_pool (default []),
                                                      user_agents list (default []),
                                                      max_sqli_payloads (default 15),
                                                      forced_browsing_delay_secs (default 0.3)

5. Derive base_url from target.target_value
6. _discover_targets(base_url, target_id) → protected path list
7. _discover_login_forms(base_url, target_id) → login URL list

8. PHASE 1 — _probe_forced_browsing(base_url, paths, settings)
   For each path (scope-checked):
     a. Direct GET — check if accessible without auth
     b. Param modification (append ?authenticated=yes, ?admin=true, ?debug=1, ?bypass=true)
     c. HTTP method override (PUT / DELETE / PATCH / HEAD)
     d. Header injection (X-Original-URL, X-Rewrite-URL, X-Forwarded-For: 127.0.0.1,
        X-Custom-IP-Authorization: 127.0.0.1, X-Host: localhost)
     e. Path traversal variants (/admin/../admin, /..;/admin, /%2e%2e/admin, /admin/.)
     f. Cookie manipulation (admin=true, role=admin, authenticated=true, is_admin=1)
     g. JWT none algorithm (if JWT token detected in response cookies/headers)
   → asyncio.sleep(forced_browsing_delay_secs) between requests

9. PHASE 2 — _probe_sqli_bypass(login_urls, settings)
   Payload list (15 classic + blind variants):
     ' OR '1'='1'--,  admin'--,  ' OR 1=1--,  " OR ""=",  ' OR 'x'='x,
     1' OR '1'='1,    ') OR ('1'='1,  ' OR 1=1#,  admin'#,
     ' OR 'unusual'='unusual'--,  1 OR 1=1,  ' OR ''=',  " OR 1=1--,
     '; DROP TABLE users;--,  1; SELECT * FROM users--
   For each login URL × payload:
     → Rotate User-Agent from settings.user_agents (cycle by index; fallback: 5 built-in browser strings)
     → Rotate X-Forwarded-For from settings.ip_rotation_pool (if populated)
     → POST {discovered_username_field: payload, discovered_password_field: 'x'}
     → asyncio.sleep(sqli_delay_secs + random.uniform(0, 0.5)) between attempts
     → On 200 + no auth-required markers → flag Vulnerability(severity=critical)
     → On 429 / lockout signal → abort remaining payloads for this URL

10. PHASE 3 — _probe_session_prediction(base_url, settings)
    Request 15 fresh session IDs via GET /
    Analyze:
      - Charset diversity (all hex? all digits? short length?)
      - Sequential delta: if IDs are numeric or hex, sort and diff
      - Entropy estimate: count unique chars, estimate bits = log2(charset_size ** id_length)
    → Flag HIGH if sequential gap < 1000 or entropy < 32 bits
    → Flag MEDIUM if entropy < 64 bits
    → Flag INFO (always emitted) summarizing sample size and estimated entropy

11. Persist summary Vulnerability(severity=info) — always, ensures ≥1 row for e2e assertion
12. Update JobState.last_tool_executed / last_seen
13. Emit TOOL_PROGRESS(100%)
14. Release semaphore
```

---

## 3. Findings & Persistence Model

All results saved as `Vulnerability` records:

```python
Vulnerability(
    target_id=target_id,
    severity=<see table below>,
    title=<see table below>,
    source_tool="auth_bypass_tester",
    section_id="4.4",
    worker_type="authentication",
    stage_name="auth_bypass",
    evidence=<dict with probe data>,
)
```

| Condition | Severity | Title |
|---|---|---|
| Protected path accessible without auth | `high` | "Forced browsing: {path} accessible without authentication" |
| Param modification bypasses auth | `high` | "Auth bypass via parameter modification: {path}?{param}={value}" |
| HTTP method override bypasses auth | `high` | "Auth bypass via HTTP method override: {method} {path}" |
| Header injection bypasses auth | `high` | "Auth bypass via header injection: {header}: {value}" |
| Path traversal bypasses auth | `high` | "Auth bypass via path traversal: {path}" |
| Cookie manipulation bypasses auth | `high` | "Auth bypass via cookie manipulation: {cookie}={value}" |
| JWT none algorithm accepted | `critical` | "JWT none algorithm bypass: authentication token accepted without signature" |
| SQLi payload bypasses login | `critical` | "SQL injection authentication bypass: {payload} on {url}" |
| 429/lockout triggered during SQLi | `info` | "SQLi probe aborted: rate limit or lockout signal at {url}" |
| Session IDs sequential (gap < 1000) | `high` | "Predictable session IDs: sequential values detected (avg gap {N})" |
| Session IDs low entropy (<32 bits) | `high` | "Predictable session IDs: entropy below 32 bits ({N:.1f} bits estimated)" |
| Session IDs medium entropy (<64 bits) | `medium` | "Weak session IDs: entropy below 64 bits ({N:.1f} bits estimated)" |
| Summary (always emitted) | `info` | "Auth bypass test complete: {N} finding(s) across {P} paths, {L} login URLs" |

---

## 4. Stealthiness Controls (Highest Priority)

| Control | Config key | Default | Behavior |
|---|---|---|---|
| SQLi inter-attempt delay | `bypass.json → sqli_delay_secs` | `2.0` | `sleep(sqli_delay_secs + random.uniform(0, 0.5))` between SQLi payloads |
| Forced browsing delay | `bypass.json → forced_browsing_delay_secs` | `0.3` | `sleep(delay)` between path probes |
| User-Agent rotation | `bypass.json → user_agents` | `[]` | Cycle through provided list; fallback: 5 built-in browser strings |
| IP rotation | `bypass.json → ip_rotation_pool` | `[]` | Cycle X-Forwarded-For; if empty, header is omitted entirely |
| Payload cap | `bypass.json → max_sqli_payloads` | `15` | Hard cap on SQLi payloads per login URL |
| Rate-limit abort | (always active) | — | On HTTP 429 or body match for "too many"/"rate limit"/"blocked"/"try again" → stop probes for that URL |
| No follow-redirects | (always active) | — | `follow_redirects=False` — redirect to login page IS the auth signal |

Built-in User-Agent fallback list:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
```

---

## 5. Configuration File

New config file: `shared/config/{target_id}/bypass.json`

Written by the orchestrator if a `bypass` key is present in the target profile. If the file does not exist, all keys use their defaults (listed above). No new orchestrator endpoint or dashboard settings UI is added in this implementation.

Example:
```json
{
  "sqli_delay_secs": 3.0,
  "forced_browsing_delay_secs": 0.5,
  "ip_rotation_pool": ["203.0.113.1", "198.51.100.42"],
  "user_agents": ["Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"],
  "max_sqli_payloads": 10
}
```

---

## 6. Three-Layer Coherence

No changes required — all three layers already have `auth_bypass` correctly wired:

| Layer | File | Status |
|---|---|---|
| Pipeline | `workers/authentication/pipeline.py` | ✅ `Stage("auth_bypass", [AuthBypassTester])` at index 2 |
| Playbooks | `shared/lib_webbh/playbooks.py` | ✅ `"auth_bypass"` listed under `"authentication"` |
| Dashboard | `dashboard/src/lib/worker-stages.ts` | ✅ `{ stageName: "auth_bypass", sectionId: "WSTG-ATHN-04" }` |

---

## 7. E2E Test Changes

File: `tests/e2e/test_authentication.py`

### 7.1 Timeout

Keep existing `300` — forced browsing is fast; SQLi with 2s delay × 15 payloads × 1 login URL ≈ 30s total; session prediction is 15 GETs.

### 7.2 New assertion callback (replaces `None`)

```python
async def _assert_auth_bypass(client, target_id):
    async with get_session() as session:
        stmt = select(func.count()).where(
            Vulnerability.target_id == target_id,
            Vulnerability.source_tool == "auth_bypass_tester",
        )
        count = (await session.execute(stmt)).scalar()
    assert count >= 1, (
        f"Expected at least 1 Vulnerability from auth_bypass_tester, got {count}"
    )

STAGE_ASSERTIONS = {
    ...
    "auth_bypass": _assert_auth_bypass,
    ...
}
```

---

## 8. Files Changed

| File | Change |
|---|---|
| `workers/authentication/tools/auth_bypass_tester.py` | Full replacement — new async `execute()` pattern |
| `tests/e2e/test_authentication.py` | Add `_assert_auth_bypass`; timeout stays at 300s |

No other files require modification (pipeline, playbooks, dashboard, concurrency, `__init__` all already correct).
