# WSTG-Aligned Restructure — 02 Safety Policy

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview

---

## Overview

The restructured framework introduces authenticated testing across multiple workers (identity_mgmt, authentication, authorization, session_mgmt, business_logic). This requires a strict safety policy to prevent accidental harm to real users or systems. The policy covers three areas:

1. **Credential management** — Who the framework authenticates as
2. **Targeting rules** — Who the framework can target for exploit validation
3. **Escalated access handling** — What happens when testing reveals unintended access

---

## Credential Management

### Campaign Creator — Two Credential Pairs

Every campaign requires two credential pairs entered during campaign creation:

**Pair 1: Tester Credentials**

The active operator identity. All authenticated testing runs as this user. This account should be a legitimate test account created specifically for the engagement — never a real user's account.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Login username or email |
| `password` | string | Yes | Login password |
| `auth_type` | enum | Yes | `form`, `basic`, `bearer`, `oauth` |
| `login_url` | string | No | URL of the login form/endpoint (auto-detected if not provided) |
| `token_field` | string | No | Name of the token cookie/header (auto-detected if not provided) |

**Pair 2: Testing User**

The permitted victim identity. Used ONLY as the target for IDOR, privilege escalation, CSRF, session hijacking validation. Workers never log in as this user — they only reference its public identifiers.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes (if different from email) | Login username |
| `email` | string | Yes | Email address |
| `profile_url` | string | No | Direct URL to this user's profile |

Note: Testing User has no password field. Workers must never need it.

### Storage

Credentials are stored in the target profile config file, not in the database. This keeps sensitive data out of PostgreSQL and limits exposure to the config volume.

```
shared/config/{target_id}/credentials.json
```

```json
{
    "tester": {
        "username": "pentest_operator",
        "password": "SecureTestP@ss123",
        "auth_type": "form",
        "login_url": "https://target.com/login",
        "token_field": "session_id"
    },
    "testing_user": {
        "username": "test_victim_user",
        "email": "testvictim@target.com",
        "profile_url": "https://target.com/users/test_victim_user"
    }
}
```

File permissions: `0600` (owner read/write only). The orchestrator creates this file during campaign setup. Workers read it at pipeline start.

### Session Management in base_tool.py

Every worker's `base_tool.py` provides two helper methods enforced at the framework level:

```python
class BaseTool(ABC):

    def __init__(self, config, target_id, ...):
        self._credentials = self._load_credentials(target_id)
        self._tester_session = None

    async def get_tester_session(self):
        """Authenticate as the Tester and return the session.

        Caches the session across tool invocations within a pipeline run.
        Re-authenticates if the session expires.
        """
        if self._tester_session and not self._tester_session.expired:
            return self._tester_session

        creds = self._credentials["tester"]
        self._tester_session = await self._authenticate(
            creds["username"],
            creds["password"],
            creds["auth_type"],
            creds.get("login_url"),
            creds.get("token_field")
        )
        return self._tester_session

    def get_target_user(self):
        """Return the Testing User's public identifiers.

        Returns username if available and different from email,
        otherwise falls back to email.
        """
        user = self._credentials["testing_user"]
        return {
            "identifier": self._get_best_identifier(user),
            "username": user.get("username"),
            "email": user.get("email"),
            "profile_url": user.get("profile_url")
        }

    def _get_best_identifier(self, user):
        """Return username if distinct from email, otherwise email."""
        username = user.get("username", "")
        email = user.get("email", "")
        if username and username != email:
            return username
        return email
```

There is no `get_testing_user_session()` method. It does not exist and must never be added. The framework architecturally prevents authenticating as the Testing User.

---

## Targeting Rules

### Five Rules — Enforced Across All Workers

**Rule 1: Authenticated sessions use Tester Credentials only.**

Every HTTP request that requires authentication uses the Tester session obtained via `get_tester_session()`. No worker, tool, or stage may authenticate as any other user under any circumstances.

**Rule 2: Victim targeting uses Testing User only.**

When a test needs to target another user (IDOR, horizontal privilege escalation, CSRF PoC, session fixation target), it targets the Testing User's identifiers obtained via `get_target_user()`. The Testing User's username, email, or profile URL may appear in manipulated request parameters — but the framework never logs in as this user.

**Rule 3: Discovered real users are documented but never acted upon.**

If testing reveals real user accounts (through enumeration, error messages, leaked data, directory listings), the framework:
- Records the finding as an `Observation` in the database
- Logs the discovery with severity and context
- Takes zero active actions against those accounts
- Never uses their identifiers in exploit payloads
- Never attempts to access their data

**Rule 4: Exploit confirmation targets Testing User exclusively.**

Any active exploit that requires a victim (IDOR read, privilege escalation, CSRF PoC, session fixation, account takeover chain) must target the Testing User. If the exploit cannot be validated against the Testing User (e.g., it requires a specific real user's state), the finding is logged as `unconfirmed` with a note explaining why confirmation was not attempted.

**Rule 5: No write operations against real user accounts or internal systems.**

Even when escalated access is gained (see below), the framework never:
- Modifies data on any real user account
- Changes passwords, settings, or permissions
- Deletes, creates, or alters records
- Executes write operations against internal services
- Accesses resources beyond confirming the initial access

### Enforcement in base_tool.py

```python
class BaseTool(ABC):

    # Blocklist of identifier sources that must never be used for targeting
    _REAL_USER_BLOCKLIST = set()  # Populated from Observation records

    def validate_target_user(self, identifier):
        """Verify that a target identifier matches the Testing User.

        Raises SafetyViolation if the identifier belongs to a real user
        or is not the designated Testing User.
        """
        testing_user = self.get_target_user()
        allowed = {
            testing_user["username"],
            testing_user["email"],
            testing_user.get("profile_url")
        }
        allowed.discard(None)
        allowed.discard("")

        if identifier in self._REAL_USER_BLOCKLIST:
            raise SafetyViolation(
                f"Attempted to target real user: {identifier}. "
                f"Only Testing User ({testing_user['identifier']}) is permitted."
            )

        if identifier not in allowed:
            self.logger.warning(
                "Target identifier does not match Testing User",
                identifier=identifier,
                testing_user=testing_user["identifier"]
            )

    async def log_discovered_user(self, username=None, email=None, source=None):
        """Record a discovered real user without taking any action."""
        self._REAL_USER_BLOCKLIST.add(username)
        self._REAL_USER_BLOCKLIST.add(email)

        async with get_session() as session:
            obs = Observation(
                target_id=self.target_id,
                asset_id=self.current_asset_id,
                observation_type="discovered_user",
                data={
                    "username": username,
                    "email": email,
                    "source": source,
                    "action_taken": "none — real user, documented only"
                },
                source_tool=self.__class__.__name__
            )
            session.add(obs)
            await session.commit()
```

---

## Escalated Access Handling

### What Constitutes Escalated Access

Escalated access occurs when testing reveals unintended access to resources beyond the Tester's authorized scope. Examples:

- Session hijacking test succeeds and grants access to another user's account
- CSRF PoC demonstrates state changes on the Testing User's behalf
- Session fixation allows taking over a session
- Privilege escalation grants admin panel access
- SSRF reaches internal services not exposed externally
- Cookie replay grants access after logout

### Response Protocol

When escalated access is detected, the tool follows a strict four-step protocol:

**Step 1: Document immediately**

Record what access was gained, how it was gained, what data is visible, and the severity.

**Step 2: Halt interaction**

Stop all further interaction with the escalated access. Do not navigate deeper, do not read additional data, do not perform any write operations.

**Step 3: Record as confirmed Vulnerability**

Write a Vulnerability record with `confirmed=True` and full PoC evidence.

**Step 4: Flag for chain worker**

Push an `EscalationContext` record that the chain worker consumes as a starting point for read-only chain discovery.

### on_escalated_access() Hook

Every tool calls this hook when unexpected access is detected:

```python
async def on_escalated_access(self, access_type, access_method,
                                session_data, data_exposed, severity):
    """Handle discovery of escalated access.

    Args:
        access_type: "user_account", "admin_panel", "internal_endpoint"
        access_method: Full attack chain description
        session_data: Token/cookie/credential that grants access
        data_exposed: Description of what's visible
        severity: "critical", "high", "medium"
    """
    # Step 1: Document
    self.logger.critical(
        "Escalated access detected",
        access_type=access_type,
        severity=severity,
        target_id=self.target_id
    )

    # Step 2: Halt — this method returns after recording,
    # tool must not continue using the escalated session

    # Step 3: Record Vulnerability
    async with get_session() as session:
        vuln = Vulnerability(
            target_id=self.target_id,
            asset_id=self.current_asset_id,
            vuln_type=f"escalated_access_{access_type}",
            severity=severity,
            confirmed=True,
            details={
                "access_type": access_type,
                "access_method": access_method,
                "data_exposed": data_exposed,
                "session_data_hash": hashlib.sha256(
                    session_data.encode()
                ).hexdigest()
            },
            source_tool=self.__class__.__name__,
            section_id=self.current_section_id,
            worker_type=self.worker_type,
            stage_name=self.current_stage_name
        )
        session.add(vuln)
        await session.flush()

        # Step 4: Flag for chain worker
        esc = EscalationContext(
            target_id=self.target_id,
            vulnerability_id=vuln.id,
            access_type=access_type,
            access_method=access_method,
            session_data=self._encrypt_session_data(session_data),
            data_exposed=data_exposed,
            severity=severity,
            section_id=self.current_section_id,
            consumed_by_chain=False
        )
        session.add(esc)
        await session.commit()

    # Push SSE event for real-time dashboard visibility
    await push_task(
        f"events:{self.target_id}",
        {
            "event": "escalated_access",
            "access_type": access_type,
            "severity": severity,
            "worker": self.worker_type,
            "stage": self.current_stage_name
        }
    )
```

### Chain Worker Integration

The chain worker's `FindingsCollector` stage queries for all unconsumed `EscalationContext` records:

```python
async def collect_escalation_contexts(self, target_id):
    async with get_session() as session:
        result = await session.execute(
            select(EscalationContext)
            .where(EscalationContext.target_id == target_id)
            .where(EscalationContext.consumed_by_chain == False)
        )
        contexts = result.scalars().all()

        for ctx in contexts:
            ctx.consumed_by_chain = True
        await session.commit()

        return contexts
```

The chain worker uses these escalated sessions as starting points for read-only probing:
- Can this access reach cloud metadata (169.254.169.254)?
- Can this access reach internal APIs not exposed externally?
- Can this access pivot to other user accounts?
- What's the blast radius?

**All chain verification follows the same rules:** read-only probing, document reachability, no modifications. The chain worker has the same `on_escalated_access()` hook — if chain probing reveals further escalation, it records a new `EscalationContext` for the next chain iteration.

### Session Data Encryption

Escalated session tokens stored in `EscalationContext.session_data` are encrypted at rest using Fernet symmetric encryption. The key is derived from the `DB_PASS` environment variable via PBKDF2.

```python
def _encrypt_session_data(self, session_data):
    """Encrypt session data before storing in EscalationContext."""
    key = self._derive_encryption_key()
    f = Fernet(key)
    return f.encrypt(session_data.encode()).decode()

def _decrypt_session_data(self, encrypted_data):
    """Decrypt session data when chain worker needs to use it."""
    key = self._derive_encryption_key()
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()
```

This ensures that even if the database is compromised, the escalated session tokens are not immediately usable.

---

## Campaign Creator UI Fields

The dashboard campaign creation form adds two new sections:

### Tester Credentials

```
┌─ Tester Credentials ──────────────────────────────┐
│                                                    │
│  Username:    [________________________]           │
│  Password:    [________________________] (masked)  │
│  Auth Type:   [form ▼]                             │
│               form | basic | bearer | oauth        │
│                                                    │
│  Advanced (optional):                              │
│  Login URL:   [________________________]           │
│  Token Field: [________________________]           │
│                                                    │
└────────────────────────────────────────────────────┘
```

### Testing User

```
┌─ Testing User (Victim Target) ─────────────────────┐
│                                                     │
│  Username:    [________________________]            │
│  Email:       [________________________]            │
│  Profile URL: [________________________] (optional) │
│                                                     │
│  ⚠ This user will be the ONLY target for           │
│    exploit validation. No password needed —         │
│    the framework never logs in as this user.        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Both sections are required before campaign creation proceeds. The orchestrator validates that both credential pairs are populated and writes them to `shared/config/{target_id}/credentials.json` before pushing the first task to the queue.

---

## Summary of Safety Guarantees

| Guarantee | Enforcement Point |
|-----------|-------------------|
| Only Tester session used for auth | `get_tester_session()` is the only auth method |
| No Testing User login method exists | `get_testing_user_session()` does not exist |
| Real users never targeted | `validate_target_user()` + blocklist |
| Discovered users documented only | `log_discovered_user()` writes Observation, takes no action |
| Escalated access halts immediately | `on_escalated_access()` records and stops |
| Session tokens encrypted at rest | Fernet encryption in EscalationContext |
| Chain worker is read-only | Same base_tool.py rules apply |
| Credentials stored outside DB | File-based config with 0600 permissions |
