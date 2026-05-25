# WSTG-IDNT-03: Test Account Provisioning Process

**Date:** 2026-05-24
**WSTG Reference:** [WSTG-IDNT-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process)
**Scope:** `identity_mgmt` worker rewrite + credential pipeline fix + frontend campaign builder update

---

## Summary

WSTG-IDNT-03 tests whether an application's account provisioning and de-provisioning workflows enforce proper authorization at every step. The existing `account_provision_tester.py` is a stub that conflates self-registration (already covered by IDNT-02) with admin-level provisioning, lacks the `make_client()`/`safe_request()` quality pattern used by IDNT-02, and has no de-provisioning or IDOR tests. This spec covers a full rewrite of that tool alongside the fixes required to make two-account credential testing functional end-to-end.

**Test objectives (from WSTG-IDNT-03):**
1. Identify which roles can provision accounts and what account types they may create
2. Verify proper identification, authorization, and vetting processes for provisioning requests
3. Test whether a provisioner can create accounts with greater privileges than their own
4. Assess if users can self-de-provision or de-provision other users' accounts
5. Examine resource handling after account removal

---

## Pre-existing gap: Credential pipeline is broken

The campaign builder constructs `credentialConfig` but only sends `has_credentials: true/false` to the backend. The orchestrator never writes `credentials.json`. The `InfrastructureMixin.get_tester_session()` / `get_target_user()` methods therefore always return `None` in production. IDNT-03's two-account IDOR tests require both accounts to be functional, making this the right time to fix the entire pipe.

---

## 5-Layer Change Set

### Layer 1 — Frontend: Campaign Builder (`dashboard/src/app/campaign/new/page.tsx`)

**What changes:**
- Rename "Tester Credentials" section → **"Account 1 — Attacker/Tester"**
- Rename "Testing User" section → **"Account 2 — Target User"**
- Add `password` + `auth_type` + `login_url` fields to Account 2 (currently missing)
- Add an amber warning banner between the two sections with the text:
  > "Two accounts are required for IDOR and de-provisioning tests (WSTG-IDNT-03, WSTG-AUTHZ). If only one account is provided, those tests will be skipped and a low-severity informational finding will be recorded."
- Fix `handleSubmit` to pass the full credential objects (not just `has_credentials: boolean`) to `api.createCampaign`

**What stays the same:** Section layout, checkbox toggles, all other form fields.

**UI structure for Account 2:**
```
[ x ] Account 2 — Target User
      Username / Email    [ _________________ ]
      Password            [ _________________ ]  (type="password")
      Auth Type           [ Form ▼ ]
      Login URL           [ _________________ ]  (optional)
```

**Validation change:** If Account 1 is enabled but Account 2 is not, show the warning but do not block submission.

---

### Layer 2 — TypeScript Types (`dashboard/src/types/schema.ts`)

Add `password`, `auth_type`, and `login_url` to `CredentialConfig.testing_user`:

```typescript
export interface CredentialConfig {
  tester: {
    username: string;
    password: string;
    auth_type: "form" | "basic" | "bearer" | "oauth";
    login_url?: string;
  } | null;
  testing_user: {
    username: string;
    email: string;
    password?: string;
    auth_type?: "form" | "basic" | "bearer" | "oauth";
    login_url?: string;
    profile_url?: string;
  } | null;
}
```

All new fields on `testing_user` are optional so existing call sites that only set username/email remain valid.

---

### Layer 3 — API Client (`dashboard/src/lib/api.ts`)

Update `createCampaign` to accept full credential objects:

```typescript
createCampaign(data: {
  name: string;
  description?: string;
  scope_config?: unknown;
  rate_limit?: number;
  tester_credentials?: CredentialConfig["tester"];
  testing_user?: CredentialConfig["testing_user"];
})
```

The body is JSON-stringified and sent as-is; the orchestrator handles persistence.

---

### Layer 4 — Orchestrator

**`orchestrator/routes/campaigns.py`**

Update `CampaignCreate` to receive full credential objects:

```python
class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[dict]
    scope_config: dict | None = None
    tester_credentials: dict | None = None   # {username, password, auth_type, login_url?}
    testing_user: dict | None = None         # {username, email, password?, auth_type?, login_url?, profile_url?}
    rate_limit: int = 50
```

After creating each target, write `shared/config/{target_id}/credentials.json`:

```python
import json, os
from pathlib import Path

def _write_credentials(target_id: int, tester: dict | None, testing_user: dict | None):
    if not tester and not testing_user:
        return
    config_dir = Path(f"shared/config/{target_id}")
    config_dir.mkdir(parents=True, exist_ok=True)
    creds_path = config_dir / "credentials.json"
    creds_path.write_text(json.dumps({
        "tester": tester,
        "testing_user": testing_user,
    }))
    os.chmod(creds_path, 0o600)
```

This function is called once per seed target after `session.commit()`.

**`orchestrator/target_expander.py`**

No changes — `_copy_credentials()` already copies the parent's `credentials.json` to child targets.

---

### Layer 5 — Shared Library + Worker

**`shared/lib_webbh/infra_mixin.py`**

Add one method:

```python
async def get_testing_user_credentials(self, target_id: int) -> Optional[dict]:
    """Get the Target User credentials for two-account IDOR testing."""
    creds = self._load_credentials(target_id)
    if creds and "testing_user" in creds:
        return creds["testing_user"]
    return None
```

**`workers/identity_mgmt/tools/account_provision_tester.py`**

Full rewrite. The embedded `build_command` script follows IDNT-02's 6-block structure.

---

## Worker Rewrite: 6-Block Design

### Shared helpers (top of script, identical pattern to IDNT-02)

```python
USER_AGENTS = [...]          # same 8-entry list as registration_tester
make_client()                # random UA, X-Forwarded-For jitter, Accept-Language
safe_request(method, url, client, max_retries=3, **kwargs)  # retry + backoff on 429/503
```

### Block 1 — Provisioning Endpoint Discovery

**Paths probed:** `/api/users`, `/api/v1/users`, `/api/accounts`, `/api/v1/accounts`, `/admin/users`, `/api/admin/users`, `/api/v1/admin/users`, `/users/create`, `/api/users/create`, `/api/v1/provision`, `/api/provision`

**Checks:**
- GET each path; collect those returning 200 or 405 into `found_provision_endpoints`
- For discovered 200 endpoints on HTTPS targets: probe the HTTP variant for redirect enforcement (missing redirect → `medium` finding)

**Output:** `found_provision_endpoints` list consumed by Blocks 2, 3, 6.

### Block 2 — Privilege Escalation at Provisioning

**For each `found_provision_endpoint`:**
- POST with elevated fields: `role=admin`, `is_admin=True`, `account_type=admin`, `user_type=administrator`, `admin=1`, `permissions=["admin"]`, `access_level=999`
- If HTTP 200/201: record `"Privilege escalation parameter accepted at provisioning"` (`high`)
- If response JSON reflects the elevated field back: record `"Registration response reflects elevated role parameter"` (`high`)
- If auth headers available (tester credentials): repeat with `Authorization: Bearer {token}` to test authenticated provisioner boundary

### Block 3 — Unauthenticated Admin Provisioning Access

**Paths probed (separate admin-namespaced set):**
`/api/admin/users`, `/admin/api/users`, `/api/internal/users`, `/internal/api/users`, `/api/v1/provision`, `/api/provision`, `/admin/accounts`, `/api/v1/accounts`

**Checks per path:**
- GET without auth: non-401/403/404/302 → `"Admin provisioning endpoint accessible without authentication"` (`high`)
- POST without auth with dummy payload: HTTP 200/201 → `"Account creation without authentication"` (`critical`)

### Block 4 — Two-Account De-Provisioning IDOR

**Requires:** `tester` credentials (Account 1 token) + `testing_user` credentials (Account 2 username/email/ID)

**Graceful degradation:** If either account is absent, emit one `"Two-account IDOR tests skipped — only one account configured"` (`info`) finding and skip the block.

**De-provisioning paths probed:**
`/api/users/{id}`, `/api/v1/users/{id}`, `/api/accounts/{id}`, `/api/users/{id}/suspend`, `/api/users/{id}/ban`, `/api/users/{id}/deactivate`, `/api/users/{id}/delete`

**Checks (using tester token, targeting testing_user):**
- DELETE `testing_user` account: HTTP 200/204 → `"IDOR: Account de-provisioning another user's account"` (`critical`)
- PATCH `{status: "suspended"}` on `testing_user`: HTTP 200 → `"IDOR: Account suspension of another user"` (`critical`)
- Same endpoints without any auth: HTTP 200/204 → `"Unauthenticated account deletion"` (`critical`)
- Self-de-provision: DELETE own tester account — HTTP 200/204 → `"Self de-provisioning allowed without re-authentication"` (`medium`)

**ID resolution strategy:** Try known testing_user identifiers in path (`username`, `email`, numeric ID guessing `1`–`5`, and `me`/`self`).

### Block 5 — Provisioning Workflow Bypass

**Activation/confirmation endpoints probed:**
`/activate`, `/api/activate`, `/api/v1/activate`, `/verify`, `/api/verify`, `/api/v1/verify`, `/confirm`, `/api/confirm`, `/api/v1/confirm`, `/api/users/activate`, `/api/v1/users/activate`

**Checks:**
- POST with `{user_id: "999999", token: "fake_{uid}"}` — HTTP 200 without "error"/"invalid" in body → `"Account activation bypass — fake token accepted"` (`high`)
- POST with `{user_id: "999999", token: ""}` → same check
- POST with `{user_id: "999999"}` (no token) → same check
- POST to `/api/users/{id}/status` with `{status: "active"}` without auth → `"Direct state promotion without workflow"` (`high`)

### Block 6 — Rate Limiting & Audit Trail

**Rate limiting (15-attempt burst, fresh `make_client()` per attempt):**
- Rapid POST to each `found_provision_endpoint` with unique username/email per attempt
- No 429/503 and no `rate_limit_patterns` match after 15 attempts → `"No rate limiting on provisioning endpoint"` (`medium`)
- No CAPTCHA indicators on discovered endpoint GET → `"No bot protection on provisioning endpoint"` (`low`)

**Audit trail probe:**
- GET `/api/audit/users`, `/api/v1/audit`, `/api/logs`, `/admin/audit`, `/api/admin/logs`
- 200 response accessible without auth → `"Audit log endpoint accessible without authentication"` (`high`)
- None of the paths exist (all 404) → `"No audit trail endpoint detected for provisioning"` (`info`)

---

## Severity Matrix

| Finding | Severity |
|---------|----------|
| Account creation without authentication | critical |
| IDOR: de-provision / suspend another user | critical |
| Privilege escalation parameter accepted at provisioning | high |
| Admin provisioning endpoint accessible without authentication | high |
| Account activation bypass | high |
| Direct state promotion without workflow | high |
| Audit log endpoint accessible without authentication | high |
| No rate limiting on provisioning endpoint | medium |
| Self de-provisioning without re-authentication | medium |
| Registration accepts invalid email format | medium |
| No HTTPS enforcement on provisioning endpoint | medium |
| No bot protection on provisioning endpoint | low |
| No audit trail endpoint detected | info |
| Two-account IDOR tests skipped — only one account configured | info |

---

## Files Changed

| File | Change type |
|------|------------|
| `dashboard/src/app/campaign/new/page.tsx` | Rewrite credential sections, fix credential passthrough |
| `dashboard/src/types/schema.ts` | Add `password`/`auth_type`/`login_url` to `testing_user` |
| `dashboard/src/lib/api.ts` | Update `createCampaign` signature |
| `orchestrator/routes/campaigns.py` | Update model, write `credentials.json` |
| `shared/lib_webbh/infra_mixin.py` | Add `get_testing_user_credentials()` |
| `workers/identity_mgmt/tools/account_provision_tester.py` | Full rewrite |

**No changes required to:**
- `workers/identity_mgmt/pipeline.py` — stage name `account_provisioning` unchanged
- `shared/lib_webbh/playbooks.py` — stage already registered
- `workers/identity_mgmt/concurrency.py` — `AccountProvisionTester` already in `TOOL_WEIGHTS` as HEAVY
- `workers/identity_mgmt/tools/__init__.py` — class name unchanged
- `tests/e2e/test_identity_mgmt.py` — stage assertion is `None` (runs, no assertion), timeout 120s

---

## Testing Strategy

- Unit: The 6 blocks are pure Python scripts run in a subprocess. Each block can be isolated and run directly against a test target with known provisioning endpoints.
- E2E: The existing `test_identity_mgmt.py` stage assertion for `account_provisioning` is `None` — it will pass as long as the stage completes without emitting a pipeline error. No change needed.
- Manual: Verify the frontend warning banner appears when Account 2 is unchecked, that credentials are written to disk after campaign creation, and that the worker picks them up.

---

## Open Questions / Constraints

- **ID guessing in Block 4:** Numeric ID guessing (`1`–`5`) is intentionally conservative. If `testing_user` has a known `profile_url`, the ID can be parsed from it — this is handled via `get_target_user()` → `profile_url`.
- **Credential security:** Passwords are stored in `credentials.json` with `chmod 0o600`. The file is never logged and is excluded from `redact_sensitive` patterns. This is the same handling as the existing tester credentials.
- **Auth_type for Account 2:** The `login_url` field allows workers to authenticate Account 2 via form POST. If not provided, the worker skips the authenticated portion of Block 4 and records it as `info`.
