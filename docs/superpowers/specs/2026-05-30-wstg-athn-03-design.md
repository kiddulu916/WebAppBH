# WSTG-ATHN-03: Testing for Weak Lock Out Mechanism — Design Spec

**Date:** 2026-05-30  
**WSTG reference:** [WSTG-ATHN-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)  
**Worker:** `authentication`  
**Stage:** `lockout_mechanism` (index 1 in STAGES, immediately after `default_credentials`)

---

## 1. Objective

Rewrite the existing `LockoutTester` stub (`workers/authentication/tools/lockout_tester.py`) to:

- Fully probe account lockout threshold (how many attempts before lockout triggers)
- Measure lockout duration via polling at 5-min, 10-min, 15-min intervals
- Detect CAPTCHA presence and test common bypass vectors
- Flag user enumeration via differing lockout error messages
- Persist all findings as `Vulnerability` records (not `Observation`) so `DefaultCredentialTester._get_lockout_threshold()` can read the threshold for its Hydra pair-selection logic
- Follow the `DefaultCredentialTester` architecture: override `execute()` directly, no subprocess embedding

---

## 2. Architecture

### 2.1 Class structure

`LockoutTester(AuthenticationTool)` in `workers/authentication/tools/lockout_tester.py`:

- Overrides `execute()` directly — no `build_command` / `parse_output`
- Uses `httpx.AsyncClient` throughout (no subprocess)
- Two sync helpers and four async helpers:

| Method | Responsibility |
|---|---|
| `_load_settings(target_id)` | **Sync.** Reads `rate_limits.json` + `custom_headers.json` from `shared/config/{target_id}/` (mirrors DefaultCredentialTester) |
| `_discover_login_urls(base_url, target_id)` | **Async.** Queries `Asset` table for `admin_interface` assets; falls back to probing a fixed path list |
| `_probe_threshold(url, username, settings)` | Sends up to `MAX_ATTEMPTS=20` wrong-password POSTs; detects lockout via HTTP 429, 403 + lockout body text, or response body shift |
| `_poll_duration(url, username, settings)` | After lockout confirmed, `asyncio.sleep(300)` between three checks (5 / 10 / 15 min); returns minutes at which auto-unlock occurs (`None` if never unlocked in 15 min) |
| `_probe_captcha(url, settings)` | Detects CAPTCHA via regex; if present, tests: (1) direct POST bypass skipping UI, (2) hidden-field value exposure, (3) resubmission of a known-good CAPTCHA token |
| `_probe_user_enum(url, username, settings)` | Compares response body/status for locked `username` vs hardcoded nonexistent sentinel `"nonexistent_user_xyz_12345"`; flags if they differ |

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
5. Derive base_url from target.target_value
6. _discover_login_urls(base_url, target_id)
7. Scope-check each URL; skip + log violations
8. For each in-scope URL:
   a. _probe_threshold(url, username, settings)
   b. If lockout detected → _poll_duration(url, username, settings)
   c. _probe_captcha(url, settings)
   d. If lockout detected → _probe_user_enum(url, username, settings)
9. Persist all findings via _save_finding()
10. Always persist a summary info Vulnerability (ensures ≥1 row for e2e assertion)
11. Update JobState.last_tool_executed / last_seen
12. Emit TOOL_PROGRESS 100% event
13. Release semaphore
```

---

## 3. Findings & Persistence Model

All results are saved as `Vulnerability` records:

```python
Vulnerability(
    target_id=target_id,
    severity=<see table below>,
    title=<see table below>,
    source_tool="lockout_tester",
    section_id="4.3",
    worker_type="authentication",
    stage_name="lockout_mechanism",
    evidence=<dict with all probe data>,
)
```

| Condition | Severity | Title |
|---|---|---|
| No lockout after 20 attempts | `high` | "No account lockout mechanism detected" |
| Auto-unlock in <5 min | `medium` | "Account lockout duration too short ({N}s)" |
| Lockout detected, duration adequate | `info` | "Account lockout triggered at attempt {N}" |
| CAPTCHA direct-POST bypass succeeds | `high` | "CAPTCHA bypassed via direct server-side POST" |
| CAPTCHA hidden-field hint found | `medium` | "CAPTCHA solution exposed in page source" |
| CAPTCHA known-token resubmission succeeds | `medium` | "CAPTCHA token reusable across sessions" |
| Locked vs unknown user responses differ | `medium` | "User enumeration via lockout error message difference" |
| Locked account enumerable vs unknown | `low` | "Locked account distinguishable from unknown account" |
| Summary (always emitted) | `info` | "Lockout test complete: {N} finding(s) across {M} URL(s)" |

The first lockout-detected `Vulnerability` record includes `evidence["lockout_at_attempt"]` — this is the key read by `DefaultCredentialTester._get_lockout_threshold()` to select conservative vs. full wordlists for Hydra.

---

## 4. Configuration

`_load_settings()` reads from `shared/config/{target_id}/`:

| File | Key | Default | Purpose |
|---|---|---|---|
| `rate_limits.json` | `lockout_probe_delay_secs` | `0.5` | Delay between failed-login attempts |
| `rate_limits.json` | `pps` | `10` | (informational, not used directly here) |
| `custom_headers.json` | `*` | `{}` | Extra headers forwarded on all requests |

Username used for threshold probing: `credentials["username"]` if passed from pipeline; falls back to `"testuser"`.

---

## 5. Duration Testing Detail

After lockout is detected at attempt N:

```
sleep(300)   → check if login succeeds → if yes: unlock_at = 5 min → MEDIUM finding
sleep(300)   → check if login succeeds → if yes: unlock_at = 10 min → INFO finding  
sleep(300)   → check if login succeeds → if yes: unlock_at = 15 min → INFO finding
(no further wait — 15 min is the WSTG standard maximum)
```

If the lockout never lifts within 15 min: recorded as `info` with `"duration": ">15 min"`.  
If unlock happens in <5 min: severity `medium` — lockout too easily waited out.

Total worst-case duration for this phase: **900 seconds (15 min)**.

---

## 6. CAPTCHA Bypass Testing Detail

Detection regex (shared with `DefaultCredentialTester`):
```python
_CAPTCHA_RE = re.compile(
    r"recaptcha|hcaptcha|h-captcha|turnstile|captcha\.js|g-recaptcha|cf-turnstile",
    re.IGNORECASE,
)
```

If CAPTCHA detected on the login page, three bypass probes run:

1. **Direct POST bypass**: Skip the login UI entirely; POST credentials directly to the form action endpoint. If response does not contain CAPTCHA challenge → bypass confirmed (`high`).

2. **Hidden-field hint**: Parse the CAPTCHA challenge page for `<input type="hidden">` fields, image `alt` text, and `<img>` filenames containing digit sequences. If a plausible solution is found → `medium`.

3. **Token resubmission**: Capture any CAPTCHA `g-recaptcha-response` / `h-captcha-response` field value from a prior response; replay it in a new request. If accepted → `medium`.

---

## 7. Scope & Safety

- All URLs are passed through `scope_manager.is_in_scope(url)` before any request is sent.
- Out-of-scope URLs are skipped; violations logged via `record_scope_violation`.
- The probe uses a single fixed username (`testuser` or configured value) — it does not iterate over real usernames to avoid production account lockout.
- Inter-request delay from `rate_limits.json.lockout_probe_delay_secs` (default 0.5s) prevents hammering.

---

## 8. Three-Layer Coherence

No changes required to pipeline, playbooks, or dashboard — all three layers already have `lockout_mechanism` correctly wired:

| Layer | File | Status |
|---|---|---|
| Pipeline | `workers/authentication/pipeline.py` | ✅ `Stage("lockout_mechanism", [LockoutTester])` at index 1 |
| Playbooks | `shared/lib_webbh/playbooks.py` | ✅ `"lockout_mechanism"` listed under `"authentication"` |
| Dashboard | `dashboard/src/lib/worker-stages.ts` | ✅ `{ stageName: "lockout_mechanism", sectionId: "WSTG-ATHN-03" }` |

---

## 9. E2E Test Changes

File: `tests/e2e/test_authentication.py`

### 9.1 Stage timeout update

```python
# Before
"lockout_mechanism": 180,

# After
"lockout_mechanism": 1050,  # threshold probe (30s) + 3x 300s duration polls + buffer
```

### 9.2 New assertion callback

```python
async def _assert_lockout_mechanism(client, target_id):
    async with get_session() as session:
        stmt = select(func.count()).where(
            Vulnerability.target_id == target_id,
            Vulnerability.source_tool == "lockout_tester",
        )
        result = await session.execute(stmt)
        count = result.scalar()
    assert count >= 1, (
        f"Expected at least 1 Vulnerability from lockout_tester, got {count}"
    )

STAGE_ASSERTIONS = {
    ...
    "lockout_mechanism": _assert_lockout_mechanism,
    ...
}
```

---

## 10. Files Changed

| File | Change |
|---|---|
| `workers/authentication/tools/lockout_tester.py` | Full rewrite |
| `tests/e2e/test_authentication.py` | Add `_assert_lockout_mechanism`; bump timeout to 1050s |

No other files require modification (pipeline, playbooks, dashboard, concurrency, __init__ all already correct).
