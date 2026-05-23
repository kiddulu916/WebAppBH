# WSTG-IDNT-01: Test Role Definitions — Design Spec

**Date:** 2026-05-22
**OWASP reference:** WSTG-IDNT-01
**Worker:** `identity_mgmt`
**Stage:** `role_definitions` (stage 1 of 5)
**Status:** Approved

---

## Background

The `role_definitions` stage already exists and is wired through all three sync layers:

| Layer | File | Entry |
|-------|------|-------|
| Pipeline | `workers/identity_mgmt/pipeline.py` | `Stage("role_definitions", [RoleEnumerator])` |
| Playbooks | `shared/lib_webbh/playbooks.py` | `"role_definitions"` under `identity_mgmt` |
| Dashboard | `dashboard/src/lib/worker-stages.ts` | `{ stageName: "role_definitions", sectionId: "WSTG-IDNT-01" }` |

The existing `RoleEnumerator` tool covers roughly half of the OWASP spec. This spec describes the enhancements needed to fully satisfy all three OWASP test objectives.

---

## OWASP WSTG-IDNT-01 Objectives

1. **Identify and document roles** used by the application.
2. **Attempt to switch, change, or access another role.**
3. **Review granularity of roles and permissions** given.

---

## Scope

**One file changed:** `workers/identity_mgmt/tools/role_enumerator.py`

No changes required to:
- `pipeline.py` — stage already defined
- `playbooks.py` — stage already registered
- `worker-stages.ts` — stage already mapped
- `test_identity_mgmt.py` — stage name and LAST_STAGE unchanged

---

## Current Coverage (existing blocks)

| Block | What it does | OWASP objective |
|-------|-------------|-----------------|
| 1 | GET common endpoints, regex-scan response body for role/permission patterns | Obj 1 — identify roles |
| 2 | POST to `/register`/`/signup` with `role=admin` payloads (JSON + form) | Obj 2 — attempt role change |
| 3 | GET admin paths without auth; flag non-4xx responses | Obj 2 — access another role |
| 4 | GET `/api/v1/roles`, `/api/permissions`, etc.; check for role JSON in 200 response | Obj 1 — identify roles |

---

## New Checks (three blocks to add)

### Block 5 — JavaScript Source Scan

**Covers:** OWASP "Source Code Analysis" technique.

1. GET the target root (`/`) and extract all `<script src="...">` URLs via regex.
2. Resolve relative URLs to absolute. Cap at 10 JS files to avoid runaway requests.
3. For each JS file, fetch and scan body for:
   - `isAdmin`, `ROLE_ADMIN`, `hasRole(`, `requiresAdmin`, `admin_required`
   - `user_type`, `permissions`, `userRole`, `accessLevel`
   - Route-guard patterns: `requiresAuth`, `adminOnly`, `roles.*includes`
4. On match: emit `medium` observation — "Role/permission logic detected in JavaScript source" with matched strings and source file URL.

Error handling: each JS fetch wrapped in `try/except`, outer block wrapped with `info` fallback observation.

---

### Block 6 — Cookie & Header Role Fuzzing

**Covers:** OWASP "Cookie Variables" and "Account Variables" techniques.

**Endpoints tested:** `/profile`, `/account`, `/api/user`, `/me`, `/api/me`

For each endpoint:
1. Baseline GET — record `status_code` and `len(response.text)`.
2. Replay GET with injected cookies: `role=admin; isAdmin=True; user_type=administrator; is_superuser=true`
3. Replay GET with injected headers: `X-Role: admin`, `X-User-Type: admin`, `X-Is-Admin: true`, `X-Forwarded-User: admin`, `X-Override-Role: administrator`

**Flag condition:** status code drops from 4xx to 2xx, OR response body grows by >20% vs. baseline.

**Finding:** `high` — "Potential privilege escalation via cookie/header role injection" with endpoint, injection method, baseline vs. modified status, and size delta.

Error handling: per-endpoint `try/except`, outer block catch-all.

---

### Block 7 — Well-Known Accounts & Role Switching

**Covers:** OWASP "Well-Known Accounts" and "Switching to Available Roles" techniques.

**Login endpoint discovery:** probe `/login`, `/api/login`, `/signin`, `/api/auth/login`, `/api/v1/login` with HEAD; use first that returns non-404.

**Credential pairs tried:**
- `admin / admin`
- `admin / password`
- `admin / 123456`
- `administrator / administrator`
- `root / root`
- `admin / Admin1!`

**Login attempt:** POST JSON `{"username": ..., "password": ...}` then form-encoded. Success signal: HTTP 200 with `token`, `access_token`, `session`, or `user` key in JSON body, or `Set-Cookie` response header present.

**On success:** emit `high` — "Default/weak admin credentials accepted" with endpoint, username, and response format.

**Role switch (credentials-first):** If `credentials` were passed, use the session token/cookie to GET each path in the admin path list. Any 200 response emits `high` — "Authenticated session reached admin endpoint" with path and status code.

Error handling: per-credential `try/except`, outer block catch-all.

---

## Output Format

All findings follow the existing observation schema (unchanged):

```python
{
    "title": str,
    "description": str,
    "severity": "info" | "medium" | "high",
    "data": dict,
}
```

Severity mapping:
- `info` — error/exception fallbacks only
- `medium` — role disclosure, JS source role logic
- `high` — privilege escalation, default credentials, unauthenticated admin access

---

## What Does Not Change

- `weight_class = WeightClass.HEAVY` — unchanged
- `parse_output` — unchanged (JSON decode of results list)
- `base_tool.py` `execute()` lifecycle — unchanged
- `concurrency.py` — unchanged
- E2E test file — unchanged (stage name, assertions, timeouts all match)

---

## Docstring Fix

Fix existing typo in class docstring: `WSTG-IDENT-001` → `WSTG-IDNT-01`.
