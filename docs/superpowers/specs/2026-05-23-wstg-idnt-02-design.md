# WSTG-IDNT-02: Test User Registration Process — Design Spec

**Date:** 2026-05-23
**OWASP reference:** WSTG-IDNT-02
**Worker:** `identity_mgmt`
**Stage:** `registration_process` (stage 2 of 5)
**Status:** Approved

---

## Background

The `registration_process` stage is already wired through all three sync layers:

| Layer | File | Entry |
|-------|------|-------|
| Pipeline | `workers/identity_mgmt/pipeline.py` | `Stage("registration_process", [RegistrationTester])` |
| Playbooks | `shared/lib_webbh/playbooks.py` | `"registration_process"` under `identity_mgmt` |
| Dashboard | `dashboard/src/lib/worker-stages.ts` | `{ stageName: "registration_process", sectionId: "WSTG-IDNT-02" }` |

The existing `RegistrationTester` has partial coverage (CAPTCHA detection, duplicate email/username, weak email format, rate limiting, bot protection). This spec describes a **full rewrite** to satisfy all OWASP WSTG-IDNT-02 test objectives with an active/intrusive testing style and WAF-aware evasion.

---

## OWASP WSTG-IDNT-02 Test Objectives

1. Verify registration information requirements align with business and security requirements.
2. Verify the registration process (self-registration vs. admin-provisioned).
3. Can the same person or identity register multiple times?
4. Can users register for different roles or permissions?
5. What proof is required for a successful registration?
6. Are registered identities verified?

---

## Scope

**Two files changed:**

| Action | Path | Responsibility |
|--------|------|----------------|
| Rewrite | `workers/identity_mgmt/tools/registration_tester.py` | Complete replacement implementing evasion layer + 6 check blocks |
| Create | `tests/unit/identity_mgmt/test_registration_tester.py` | TDD unit tests (parse_output, build_command, per-block content assertions) |

No changes to:
- `pipeline.py` — stage already defined
- `playbooks.py` — stage already registered
- `worker-stages.ts` — stage already mapped
- `concurrency.py` — `WeightClass.HEAVY` unchanged
- `tests/e2e/test_identity_mgmt.py` — stage name, assertions, and timeouts unchanged

---

## Evasion Infrastructure

Defined at the top of the inline subprocess script, used by all blocks.

### `USER_AGENTS` pool (8 strings)
Covers diverse real-browser fingerprints:
- Chrome 124 / Windows 10
- Firefox 125 / Linux
- Safari 17 / macOS
- Edge 124 / Windows 11
- Chrome 124 / Android 14
- Safari 17 / iOS 17
- Firefox 125 / macOS
- Chrome 124 / macOS

### `XFF_POOL` generator
Produces random IPs in residential-looking ranges that avoid RFC1918 private space and known cloud CIDR blocks:
- `68.x.x.x` (Comcast residential)
- `76.x.x.x` (AT&T residential)
- `172.58.x.x` (T-Mobile wireless)
- `108.x.x.x` (Spectrum residential)

### `make_client()`
Returns a fresh `httpx.Client(follow_redirects=True, timeout=10, verify=False)` with:
- `User-Agent` drawn randomly from the pool
- `X-Forwarded-For` set to a random XFF pool IP
- `Accept-Language` varied across `en-US,en;q=0.9`, `en-GB,en;q=0.8`, `fr-FR,fr;q=0.9`, `de-DE,de;q=0.9`
- `Referer` spoofed as a Google/Bing/DuckDuckGo search result URL

### `safe_request(method, url, client, *, max_retries=3, **kwargs)`
Wraps every HTTP call:
- Sleeps `random.uniform(0.3, 1.5)` seconds before the request (pre-request jitter)
- On `429` or `503`: exponential backoff — `2s → 4s → 8s` — up to `max_retries`
- Returns `None` on connect error, timeout, or exhausted retries (never raises)

A fresh `make_client()` is called at the start of each block, and again per individual attempt within Block 2 (privilege escalation) and Block 6 (rate limiting) where client identity rotation matters most.

---

## Test Blocks

### Block 1 — Endpoint Discovery & Protocol Check (passive)

Probes 14 common registration paths via `safe_request(GET)`:
```
/register, /signup, /api/register, /api/signup,
/auth/register, /auth/signup, /api/v1/register, /api/v1/signup,
/user/register, /user/signup, /api/user/register,
/account/create, /api/account/create, /join
```

For each endpoint returning 200:
- **Protocol enforcement:** Re-request the same path over `http://`. If the response is not a redirect (3xx) to HTTPS, emit `medium` — "Registration endpoint does not enforce HTTPS".
- **CSRF token:** Scan response HTML for patterns (`_token`, `csrf`, `__RequestVerificationToken`, `authenticity_token`). If absent, emit `medium` — "Registration form missing CSRF token".

Stores discovered endpoints for use by subsequent blocks.

---

### Block 2 — Privilege Escalation via Registration Parameters (active)

**Covers:** OWASP objective 4 — can users register for different roles/permissions?

For each discovered endpoint, sends 6 POST payloads with a fresh `make_client()` per attempt. Each payload uses otherwise-valid registration data (unique username, valid email, strong password) but injects one role-elevation field:

| Injected field | JSON value |
|---------------|-----------|
| `role` | `"admin"` |
| `is_admin` | `true` |
| `account_type` | `"admin"` |
| `user_type` | `"administrator"` |
| `admin` | `1` |
| `permissions` | `["admin"]` |

**Flag conditions:**
- Response status 200/201 → `high` — "Privilege escalation parameter accepted at registration"
- Response body, when parsed as JSON, contains the injected key with the elevated value (e.g., `response_json.get("role") == "admin"`) → `high` — "Registration response reflects elevated role parameter"

Error handling: per-attempt `try/except`, outer block catch-all emits `info`.

---

### Block 3 — Password Policy Enforcement (active)

**Covers:** OWASP objective 1 — registration information requirements.

Tests the following weak passwords against each discovered endpoint (fresh `make_client()` per attempt):

| Password | Weakness |
|----------|---------|
| `password` | Dictionary word |
| `123456` | Sequential numeric |
| `abc` | Too short |
| `1` | Single character |
| `` (empty string) | No password |
| Same as username | Username reuse |

**Flag condition:** Any attempt returns 200/201 without a rejection signal → `high` — "Weak password accepted at registration" with the accepted password pattern recorded.

Error handling: per-attempt `try/except`, outer block catch-all emits `info`.

---

### Block 4 — Duplicate Account & Enumeration (active)

**Covers:** OWASP objective 3 — can the same identity register multiple times?

**Duplicate email:** Registers the same email address twice (with different usernames). Flags:
- 200/201 on second attempt → `high` — "Duplicate email registration accepted"
- Rejection message explicitly names the email (`"email already registered"`, `"email taken"`, `"already in use"`) → `medium` — "Email enumeration via registration rejection message"

**Duplicate username:** Registers the same username twice (with different emails). Flags:
- 200/201 on second attempt → `high` — "Duplicate username registration accepted"
- Rejection message explicitly names the username → `medium` — "Username enumeration via registration rejection message"

**Timing-based enumeration:** Measures response time for a known-duplicate attempt vs. a novel-email attempt. Delta >500ms on repeated duplicate attempts → `low` — "Possible timing-based user enumeration at registration".

Error handling: per-attempt `try/except`, outer block catch-all emits `info`.

---

### Block 5 — Email Verification & Identity Verification (active)

**Covers:** OWASP objectives 5 and 6 — what proof is required, are identities verified?

For each discovered endpoint, tests:
- **Invalid email format:** `notanemail` — 200/201 acceptance → `medium` — "Registration accepts invalid email format"
- **Disposable domains:** `@tempmail.com`, `@mailinator.com`, `@guerrillamail.com` — 200/201 acceptance → `low` — "Registration accepts disposable email domain"
- **No verification step:** Valid email registration that returns 200/201 without any of `verify`, `confirm`, `activation`, `check your email` in response body → `medium` — "Registration may not require email verification"

Error handling: per-attempt `try/except`, outer block catch-all emits `info`.

---

### Block 6 — Rate Limiting & Bot Protection (active, WAF-aware)

**Covers:** OWASP objective 2 — are registrations protected against automated attacks?

Sends 15 registration attempts. Each attempt uses a fresh `make_client()` (new UA, new XFF) and routes through `safe_request` (pre-request jitter, backoff on 429). Stops early on 429/503 or body hint (`rate limit`, `too many requests`, `slow down`).

**Flag conditions:**
- No rate-limit response or body hint within 15 attempts → `medium` — "No rate limiting on registration endpoint"
- No CAPTCHA indicators (`g-recaptcha`, `h-captcha`, `cf-turnstile`, `data-sitekey`) detected on registration page HTML → `low` — "No bot protection detected on registration endpoint"

Error handling: per-attempt `try/except`, outer block catch-all emits `info`.

---

## Output Format

All findings follow the existing `_process_result` observation schema (unchanged):

```python
{
    "title": str,
    "description": str,
    "severity": "info" | "low" | "medium" | "high",
    "data": dict,
}
```

Severity mapping:
- `info` — error/exception fallbacks only
- `low` — timing hints, missing bot protection, disposable email accepted
- `medium` — CSRF absent, HTTPS not enforced, enumeration via error messages, no email verification, no rate limiting
- `high` — privilege escalation accepted, weak password accepted, duplicate registration accepted

---

## What Does Not Change

- `weight_class = WeightClass.HEAVY` — unchanged
- `parse_output` — unchanged (JSON decode, empty list on error)
- `base_tool.py` `execute()` lifecycle — unchanged
- `concurrency.py` — unchanged
- `pipeline.py`, `playbooks.py`, `worker-stages.ts` — unchanged (three-layer sync already correct)
- `tests/e2e/test_identity_mgmt.py` — unchanged

---

## Unit Test Strategy (TDD)

Tests assert on script content and `compile()` validity — no live HTTP. Follows the same structure as `test_role_enumerator.py`.

| Test class | Assertions |
|-----------|-----------|
| `parse_output` | Valid JSON round-trip, empty list, malformed JSON, all severity levels preserved |
| `build_command` basics | Returns `["python3", "-c", <str>]`, embeds base URL (https:// prefix), valid Python syntax |
| Evasion layer | `USER_AGENTS` in script, `X-Forwarded-For` in script, `safe_request` in script, `make_client` in script, backoff logic present |
| Block 2 (priv esc) | `role=admin` present, `is_admin` present, `account_type` present, `permissions` present |
| Block 3 (password policy) | `weak_passwords` var present, `123456` in script, `password` in script |
| Block 4 (duplicate) | Duplicate detection logic present, timing-delta variable present |
| Block 5 (email verification) | `tempmail` in script, `mailinator` in script, verification keyword check present |
| Block 6 (rate limiting) | 15-attempt count present, fresh `make_client()` per attempt, backoff via `safe_request` |
