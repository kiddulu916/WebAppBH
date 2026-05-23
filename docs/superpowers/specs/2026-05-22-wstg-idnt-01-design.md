# WSTG-IDNT-01: Test Role Definitions — Design Spec

**Date:** 2026-05-22
**WSTG section:** WSTG-IDNT-01
**Worker:** `identity_mgmt`
**Stage:** `role_definitions`

---

## 1. Context

The `role_definitions` stage already exists in all three coherence layers:

- `workers/identity_mgmt/pipeline.py` — `Stage("role_definitions", [RoleEnumerator])`
- `shared/lib_webbh/playbooks.py` — `"role_definitions"` listed under `identity_mgmt`
- `dashboard/src/lib/worker-stages.ts` — `{ stageName: "role_definitions", sectionId: "WSTG-IDNT-01" }`

**No three-layer changes are required.** All work is confined to the tool implementation, base storage layer, and e2e test.

The existing `RoleEnumerator` tool has partial coverage but is missing the two primary WSTG-IDNT-01 attack vectors (cookie-based role fuzzing and JWT claim manipulation) and uses the wrong DB model for persisting findings.

---

## 2. WSTG-IDNT-01 Objectives

The three objectives from the OWASP spec map directly to the three functions implemented:

| Objective | Function | WSTG technique |
|---|---|---|
| Identify and document roles | `discover_roles()` | Endpoint probing, HTML comment scanning, API role enumeration |
| Attempt role switching | `test_role_switching()` | Cookie parameter fuzzing, JWT `alg=none` bypass, registration injection |
| Review role permission granularity | `review_permissions()` | Unauthenticated access to admin/restricted paths |

---

## 3. Files changed

| File | Change |
|---|---|
| `workers/identity_mgmt/tools/role_enumerator.py` | Full rewrite — three-function subprocess script |
| `workers/identity_mgmt/base_tool.py` | Fix `_process_result` — swap `Observation` for `Vulnerability` |
| `tests/e2e/test_identity_mgmt.py` | Fix `role_definitions` and `registration_process` assertions |

---

## 4. `role_enumerator.py` — Script structure

The tool runs a single inline Python script via `python3 -c`. The script is organized into three named functions corresponding to WSTG-IDNT-01 objectives. All three functions run sequentially and their results are merged before printing JSON to stdout.

### 4.1 `discover_roles(base_url, auth_headers)` — Objective 1

Probes the application for role and permission references:

- **Endpoint sweep:** GET ~20 common endpoints (`/register`, `/profile`, `/api/user`, `/me`, `/settings`, `/dashboard`, etc.) and apply regex patterns against the response body:
  - `role`, `user_type`, `user_role` key–value pairs (JSON)
  - `is_admin`, `is_superuser` boolean flags
  - `permissions`, `privileges` arrays/objects
- **HTML comment scan:** Extract `<!-- ... -->` blocks from HTML responses and search for role-related keywords (`role`, `admin`, `privilege`, `permission`, `superuser`). Finding role info in comments indicates developer leakage.
- **API role enumeration:** GET `/api/roles`, `/api/v1/roles`, `/api/permissions`, `/api/v1/permissions`; flag if 200 and response body contains role/permission data.

**Severity:** `info` for JSON/HTML body matches, `low` for HTML comment leakage.

### 4.2 `test_role_switching(base_url, auth_headers)` — Objective 2

Tests whether unauthorized role escalation is actually achievable:

**Cookie-based role fuzzing (new):**
- Replay GET requests to auth-required paths with added cookies: `role=admin`, `isAdmin=True`, `user_type=administrator`, `is_superuser=1`
- Flag responses where status is 200 and body contains indicators of elevated access (admin dashboard keywords, user list data, config data)
- Severity: `high` if accepted

**JWT detection and `alg=none` bypass (new):**
- Scan response `Set-Cookie` and `Authorization` headers for JWT-shaped values (three base64url segments separated by `.`)
- Decode the payload (middle segment), look for role/permission claims (`role`, `is_admin`, `user_type`, `permissions`)
- Construct a tampered token: header `{"alg":"none","typ":"JWT"}`, payload with `"role":"admin"` and `"is_admin":true`, empty signature
- Replay the original request with the tampered token in the same position (cookie or header)
- Flag if the server returns 200 with indicators of elevated access
- Severity: `critical` if accepted

**Registration parameter injection (existing, improved):**
- POST to registration endpoints with `role=admin`, `user_type=administrator`, `is_admin=true` in both JSON and form bodies
- Improved heuristics: flag only if response body contains the injected role value in an account-context key (not just anywhere in the body)
- Severity: `medium` for ambiguous acceptance, `high` for confirmed role in response

### 4.3 `review_permissions(base_url, auth_headers)` — Objective 3

Checks whether restricted paths are accessible without authentication:

- GET a list of admin/privileged paths: `/admin`, `/admin/dashboard`, `/admin/users`, `/admin/settings`, `/administrator`, `/manage`, `/mod`, `/backups`, `/support/admin`, `/api/admin/users`, `/api/admin/config`
- Flag any path that returns a status code **not in** `{401, 403, 404, 302, 301}`
- Severity: `high` for accessible restricted paths

---

## 5. `base_tool.py` — Storage fix

### Problem

`_process_result` currently creates:
```python
Observation(
    target_id=target_id,          # not a column in observations table
    observation_type="identity",  # not a column
    title=...,                    # not a column
    severity=...,                 # not a column
    data=...,                     # not a column
    source_tool=...,              # not a column
)
```

The `observations` table schema is `(asset_id NOT NULL, tech_stack, page_title, status_code, headers)` — for HTTP technology observations, not security findings. This commit silently fails or produces malformed rows.

### Fix

Replace with `Vulnerability` (the correct model for security findings, as established by `config_mgmt`):

```python
vuln = Vulnerability(
    target_id=target_id,
    title=item["title"],
    severity=item.get("severity", "info"),
    description=item.get("description", ""),
    source_tool=self.name,
    section_id=item.get("section_id", "WSTG-IDNT-01"),
    worker_type="identity_mgmt",
    stage_name=item.get("stage_name", self.name),
    evidence=item.get("data", {}),
)
```

Add a dedup check on `(target_id, title)` before inserting (same pattern as `config_mgmt`). Emit `NEW_VULNERABILITY` event instead of `NEW_OBSERVATION`.

Imports to update: remove `Observation`, add `Vulnerability` and `select`.

---

## 6. Severity mapping

| Finding | Severity |
|---|---|
| Role/permission reference in JSON or HTML response body | `info` |
| Role keyword found in HTML comment | `low` |
| Registration with injected role accepted (ambiguous) | `medium` |
| Registration with injected role confirmed in response account context | `high` |
| Cookie-based role parameter accepted | `high` |
| JWT `alg=none` accepted with tampered role claims | `critical` |
| Admin/restricted path accessible without authentication | `high` |

---

## 7. E2E test changes

`tests/e2e/test_identity_mgmt.py`:

- `role_definitions` assertion: `assert_assets` → `assert_vulnerabilities`
- `registration_process` assertion: `assert_assets` → `assert_vulnerabilities` (base_tool fix affects all stages)

The `assert_vulnerabilities` helper already exists in `tests/conftest.py`.

---

## 8. Out of scope

- No changes to `pipeline.py`, `playbooks.py`, or `worker-stages.ts` (three-layer coherence is already correct)
- No changes to the other four identity_mgmt tools (`registration_tester.py`, `account_provision_tester.py`, `account_enumerator.py`, `username_policy_tester.py`) beyond the base_tool storage fix they inherit
- The `authentication` worker's identical `_process_result` bug is a separate PR
