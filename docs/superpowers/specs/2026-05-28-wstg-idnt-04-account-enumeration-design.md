# WSTG-IDNT-04 — Account Enumeration & Guessable User Account (faithful re-implementation)

- **Date:** 2026-05-28
- **WSTG ID:** WSTG-IDNT-04
- **Worker / stage:** `identity_mgmt` / `account_enumeration`
- **Tool:** `AccountEnumerator`
- **Source:** [OWASP WSTG-IDNT-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account) plus its reference links (general username-enumeration techniques, WordPress username enumeration).

## Problem

The `account_enumeration` stage already exists and is wired into all three coherence layers, but its `AccountEnumerator` tool is a shallow ~420-line inline `python3 -c` script. It compares a handful of common usernames against one another with **no known-valid/known-invalid oracle** — the core of the OWASP methodology ("the application should answer in the same manner for every failed attempt"). Any difference between two arbitrary usernames is reported, producing false positives, and several techniques from the guide and its reference links are missing entirely.

This is an enhancement / faithful re-implementation of one existing tool. It is **not** a new pipeline stage.

## Goals

- Implement the OWASP baseline-delta oracle methodology faithfully.
- Cover all techniques from the guide and reference links (login, reset+timing, registration, URI/profile probing, predictable-username generation, WordPress/REST enumeration).
- Make the tool unit-testable (extract a standalone module; replace string-substring "tests").
- Expose conservative, operator-tunable parameters in the dashboard Settings Drawer to manage the lockout/WAF-ban risk the guide warns about.

## Non-goals

- No new pipeline stage; no changes to `pipeline.py`, `playbooks.py`, or `worker-stages.ts` (three-layer coherence already intact).
- No DB/model changes — findings remain `Observation` rows (`observation_type="identity"`) via the existing `base_tool._process_result`.
- Staff-impersonation / reserved-username testing remains in `username_policy_tester` (WSTG-IDNT-05); it is **not** duplicated here.

## Architecture

### Component structure

Replace the single inline-script tool with two files:

1. **`workers/identity_mgmt/tools/account_enum_probe.py`** — standalone, dependency-light module (`httpx` + stdlib only; **no** `lib_webbh`/DB imports, so it runs and tests in isolation). Contains:
   - Pure functions for the oracle and each technique.
   - A `DEFAULTS` config dict.
   - A `__main__` entry that reads a JSON config from `--config`, runs enabled techniques, and prints a JSON findings array to stdout.

2. **`workers/identity_mgmt/tools/account_enumerator.py`** — slimmed to a thin wrapper over `IdentityMgmtTool`:
   - `build_command(target, credentials)`: merges `target.target_profile.get("account_enum", {})` over module `DEFAULTS`, injects `base_url` and auth token, serializes to JSON, and returns `["python3", "-m", "workers.identity_mgmt.tools.account_enum_probe", "--config", <json>]`. (`python3 -m workers.…` resolves because `workers` is already an importable package in the container, as `pipeline.py` demonstrates.)
   - `parse_output(stdout)`: unchanged JSON-loads-with-empty-list fallback.

The stage wiring `Stage("account_enumeration", [AccountEnumerator])` is unchanged; `base_tool.execute()` continues to drive cooldown, semaphore, subprocess, parse, and `Observation` insert.

### The oracle (baseline-delta methodology)

A `ResponseSignature` captures: `status_code`, `redirect_location`, `normalized_body_length`, a `body_snippet`/hash, and `response_time_ms`.

Per endpoint:

1. **Learn noise.** Send a guaranteed-invalid username (long random string) `baseline_samples` times (default 3); record natural jitter in body length and timing.
2. **Probe candidates.** Build a signature for each candidate.
3. **Decide.** Flag a candidate "distinguishable" only when its signature diverges from the invalid baseline beyond the learned noise band: status differs, redirect target differs, body length outside `jitter ± margin`, or timing delta beyond a multiple of observed jitter.
4. **Corroborate (secondary only).** Keyword matching ("invalid password" vs "user not found", "already taken", reset "email sent") raises confidence/severity but is **never** the sole trigger.

Each finding records the technique, the distinguishing dimension, the candidates judged valid, and a confidence/severity.

### Techniques (all six, each toggleable)

1. **`login_oracle`** — login endpoints; valid-vs-invalid via baseline-delta (status/length/body/redirect).
2. **`reset_oracle`** — forgot/reset endpoints; response delta **plus** a timing oracle (external-email send adds latency — guide's "Analyzing Response Times").
3. **`reg_oracle`** — registration "username/email already taken" as an enumeration signal (enumeration aspect only).
4. **`uri_probe`** — `/user/<name>`-style paths: 403-vs-404 distinction, friendly-404 detection (200 with not-found body/image), and `<title>` analysis ("Invalid user").
5. **`pattern_gen`** — generate candidates from observed patterns (sequential `CN000100…`, realm-alias `R1001`, first-initial+lastname); each validated through the oracle, never blindly reported; total generated candidates capped.
6. **`cms_wp`** (reference links) — WordPress `/?author=N` → 301 redirect to `/author/<slug>/`, and `/wp-json/wp/v2/users` REST listing.

Evasion conventions reused from sibling tools: rotating `USER_AGENTS`, `X-Forwarded-For`, a `safe_request` helper with 429 backoff + jitter, and `follow_redirects=False` where the redirect location is itself the signal.

## Settings Drawer tunables

New profile block `target_profile["account_enum"]`, with module `DEFAULTS` as fallback:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `enabled` | bool | `true` | master switch |
| `techniques` | `{login_oracle, reset_oracle, reg_oracle, uri_probe, pattern_gen, cms_wp: bool}` | all `true` | per-technique toggles |
| `max_candidates` | int | `6` | cap on usernames/emails probed per endpoint |
| `request_delay_ms` | int | `150` | inter-request delay (lockout/WAF safety) |
| `baseline_samples` | int | `3` | noise-learning samples |
| `timing_samples` | int | `2` | samples per candidate for the timing oracle |
| `custom_seeds` | string[] | `[]` | operator-supplied seed usernames/emails |

### Plumbing (4 layers)

- **Orchestrator** (`orchestrator/main.py`): add `account_enum: Optional[dict] = None` to `TargetProfileUpdate`; merge into `profile` in `update_target_profile` (same pattern as `custom_headers` / `rate_limits`).
- **Dashboard types** (`dashboard/src/types/schema.ts` and `shared/interfaces.ts`): add optional `account_enum` to `TargetProfile` (the TS interface already has an index signature, so this is additive).
- **API client** (`dashboard/src/lib/api.ts`): extend the `updateTargetProfile` param type to include `account_enum`.
- **UI** (`dashboard/src/components/c2/SettingsDrawer.tsx`): a collapsible "Account Enumeration (WSTG-IDNT-04)" section — master toggle, six technique checkboxes, `max_candidates` / `request_delay_ms` number inputs, and a `custom_seeds` textarea — saved through the existing `handleSave` → `updateTargetProfile` flow.
- **Worker**: reads `target.target_profile.get("account_enum", {})` in `build_command`. No `pipeline.py` / `main.py` changes — the ORM `target` (carrying `target_profile`) already reaches `build_command`.

## Error handling & safety

- The probe module never raises out: each technique is wrapped; failures become an `info`-severity diagnostic finding (preserves current behavior).
- Honors `enabled=false` (emit nothing), respects `max_candidates` and `request_delay_ms`, and caps `pattern_gen` output.
- Relies on the existing `TOOL_TIMEOUT` subprocess guard and the worker's scope checks.
- Conservative defaults + operator-tunable budget address the guide's lockout/IP-ban warning.

## Testing

Real unit tests in `tests/unit/identity_mgmt/test_account_enum_probe.py` (matching the existing `tests/unit/identity_mgmt/` layout), exercising pure functions directly:

- signature divergence vs jitter band (valid flagged; baseline noise not),
- keyword corroboration is secondary-only (never sole trigger),
- pattern generators (`CN000100`, realm alias, initial+lastname),
- WordPress redirect / REST-listing parsers,
- config merge (profile overrides defaults; `enabled=false` ⇒ empty findings).

Plus `test_account_enumerator.py` wrapper tests: command shape (`python3 -m …`), JSON config embedded and parseable, scheme handling, and `parse_output` robustness.

HTTP is mocked with httpx `MockTransport` (no new dependency) so tests need no network. No disposable validation scripts — all verification runs under pytest.

## Files touched

**New**
- `workers/identity_mgmt/tools/account_enum_probe.py`
- `tests/unit/identity_mgmt/test_account_enum_probe.py`
- `tests/unit/identity_mgmt/test_account_enumerator.py`

**Modified**
- `workers/identity_mgmt/tools/account_enumerator.py` (slim wrapper)
- `orchestrator/main.py` (`TargetProfileUpdate` + `update_target_profile`)
- `dashboard/src/types/schema.ts` (`TargetProfile`)
- `shared/interfaces.ts` (`TargetProfile`)
- `dashboard/src/lib/api.ts` (`updateTargetProfile` param type)
- `dashboard/src/components/c2/SettingsDrawer.tsx` (new section)

**Unchanged (coherence already intact)**
- `workers/identity_mgmt/pipeline.py`, `shared/lib_webbh/playbooks.py`, `dashboard/src/lib/worker-stages.ts`
