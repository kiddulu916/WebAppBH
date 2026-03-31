# M6: Identity, Authentication, Authorization & Session Workers Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build four credential-dependent workers for identity management (5 stages), authentication testing (10 stages), authorization bypass detection (4 stages), and session management analysis (9 stages), including escalated access handling and session data encryption.

**Architecture:** Four separate workers following the worker template. All check for `credentials.json` at startup and skip if missing. Session management includes `EscalationContext` model integration for discovered user sessions.

**Tech Stack:** Python 3.10, asyncio, lib_webbh (database, messaging, scope, infra_mixin), cryptography (Fernet), Docker.

**Design docs:** `docs/plans/design/2026-03-29-restructure-05-identity-auth-authz-session.md`

---

## M6a: Identity Management Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `identity_mgmt` |
| `{WORKER_DIR}` | `workers/identity_mgmt` |
| `{BASE_TOOL_CLASS}` | `IdentityMgmtTool` |
| `{EXPECTED_STAGE_COUNT}` | `5` |

### Stages (WSTG 4.3.1 → 4.3.5)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | role_definitions | 4.3.1 | RoleEnumerator |
| 2 | registration_process | 4.3.2 | RegistrationTester |
| 3 | account_provisioning | 4.3.3 | AccountProvisionTester |
| 4 | account_enumeration | 4.3.4 | AccountEnumerator |
| 5 | weak_username_policy | 4.3.5 | UsernamePolicyTester |

### Base Tool Helpers

Credential-dependent worker — adds `get_tester_session()`, `get_target_user()`, `validate_target_user()` from InfrastructureMixin.

---

## M6b: Authentication Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `authentication` |
| `{WORKER_DIR}` | `workers/authentication` |
| `{BASE_TOOL_CLASS}` | `AuthenticationTool` |
| `{EXPECTED_STAGE_COUNT}` | `10` |

### Stages (WSTG 4.4.1 → 4.4.10)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | credentials_transport | 4.4.1 | CredentialTransportTester |
| 2 | default_credentials | 4.4.2 | DefaultCredentialTester |
| 3 | lockout_mechanism | 4.4.3 | LockoutTester |
| 4 | auth_bypass | 4.4.4 | AuthBypassTester |
| 5 | remember_password | 4.4.5 | RememberPasswordTester |
| 6 | browser_cache | 4.4.6 | BrowserCacheWeaknessTester |
| 7 | weak_password_policy | 4.4.7 | PasswordPolicyTester |
| 8 | security_questions | 4.4.8 | SecurityQuestionTester |
| 9 | password_change | 4.4.9 | PasswordChangeTester |
| 10 | multi_channel_auth | 4.4.10 | MultiChannelAuthTester |

---

## M6c: Authorization Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `authorization` |
| `{WORKER_DIR}` | `workers/authorization` |
| `{BASE_TOOL_CLASS}` | `AuthorizationTool` |
| `{EXPECTED_STAGE_COUNT}` | `4` |

### Stages (WSTG 4.5.1 → 4.5.4)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | directory_traversal | 4.5.1 | DirectoryTraversalTester |
| 2 | authz_bypass | 4.5.2 | AuthzBypassTester |
| 3 | privilege_escalation | 4.5.3 | PrivilegeEscalationTester |
| 4 | idor | 4.5.4 | IdorTester |

---

## M6d: Session Management Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `session_mgmt` |
| `{WORKER_DIR}` | `workers/session_mgmt` |
| `{BASE_TOOL_CLASS}` | `SessionMgmtTool` |
| `{EXPECTED_STAGE_COUNT}` | `9` |

### Stages (WSTG 4.6.1 → 4.6.9)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | session_scheme | 4.6.1 | SessionSchemeTester |
| 2 | cookie_attributes | 4.6.2 | CookieAttributeTester |
| 3 | session_fixation | 4.6.3 | SessionFixationTester |
| 4 | exposed_variables | 4.6.4 | SessionVariableTester |
| 5 | csrf | 4.6.5 | CsrfTester |
| 6 | logout_functionality | 4.6.6 | LogoutTester |
| 7 | session_timeout | 4.6.7 | SessionTimeoutTester |
| 8 | session_puzzling | 4.6.8 | SessionPuzzlingTester |
| 9 | session_hijacking | 4.6.9 | SessionHijackingTester |

### Escalated Access Integration

Session management tools may discover access to real user sessions. The base_tool includes `on_escalated_access()` from InfrastructureMixin — tools call this method to document access, encrypt session data, and create an EscalationContext record.

```python
# In session_mgmt/base_tool.py
    async def on_escalated_access(self, target_id, access_type, access_method, session_data, data_exposed, severity):
        """Document escalated access and halt further probing."""
        from lib_webbh.database import get_session, EscalationContext, Vulnerability
        from cryptography.fernet import Fernet
        import os

        # Encrypt session data at rest
        key = os.environ.get("FERNET_KEY", Fernet.generate_key().decode())
        f = Fernet(key.encode() if isinstance(key, str) else key)
        encrypted = f.encrypt(session_data.encode()).decode()

        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                severity=severity,
                title=f"Escalated Access: {access_type}",
                worker_type=self.worker_type,
                vuln_type="escalated_access",
                confirmed=True,
            )
            session.add(vuln)
            await session.flush()

            esc = EscalationContext(
                target_id=target_id,
                vulnerability_id=vuln.id,
                access_type=access_type,
                access_method=access_method,
                session_data=encrypted,
                data_exposed=data_exposed,
                severity=severity,
            )
            session.add(esc)
            await session.commit()
```

---

## M6 Skip Logic

All four workers in M6 check for credentials at startup. If no `shared/config/{target_id}/credentials.json` exists, the worker immediately records a skip and exits:

```python
# In each M6 worker's main.py
async def run_pipeline(target_id: int):
    creds_path = Path(f"shared/config/{target_id}/credentials.json")
    if not creds_path.exists():
        async with get_session() as session:
            job = JobState(
                target_id=target_id,
                container_name=WORKER_TYPE,
                status="complete",
                skipped=True,
                skip_reason="no credentials provided",
            )
            session.add(job)
            await session.commit()
        return
    # ... proceed with pipeline
```

---

## Implementation Tasks

Since M6 consists of 4 separate workers, implement them sequentially: identity_mgmt → authentication → authorization + session_mgmt (parallel).

For each worker, follow the worker template tasks T1–T8, adapted for credential-dependent logic.

**Note:** Add InfrastructureMixin import and escalated access handling to session_mgmt base_tool.