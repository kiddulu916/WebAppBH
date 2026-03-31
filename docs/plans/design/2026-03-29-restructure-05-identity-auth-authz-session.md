# WSTG-Aligned Restructure — 05 Identity, Authentication, Authorization, Session Workers

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-02-safety-policy
**WSTG Sections:** 4.3, 4.4, 4.5, 4.6

---

## Overview

These four workers form the authentication chain — they must run in sequence because each depends on the output of its predecessor:

```
config_mgmt → identity_mgmt → authentication → authorization
                                              → session_mgmt
```

All four workers are governed by the Safety Policy (restructure-02). They use Tester Credentials for all authenticated testing and target only the Testing User for exploit validation.

---

# Identity Management Worker (4.3)

**Worker Directory:** `workers/identity_mgmt/`
**Queue:** `identity_mgmt_queue`
**Trigger:** config_mgmt complete
**Stages:** 5

---

### Stage 1: role_definitions (Section 4.3.1)

**Objective:** Enumerate the roles defined in the application and validate that role boundaries are clearly enforced.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| RoleEnumerator | New | LIGHT | Authenticates as Tester and crawls the application, collecting all accessible pages, menu items, and API endpoints. Builds a role-permission map by: (1) Identifying role indicators in responses — dashboards showing user role, navigation menus with role-specific items, API responses with permission fields. (2) Comparing accessible resources against the Testing User's profile URL to infer Testing User's role. (3) Checking for role parameters in requests/cookies that could be manipulated (`role`, `group`, `access_level`, `is_admin`, `user_type`). Stores as Observation records with `observation_type="role_map"`. |

**Input requirements:** Tester Credentials (auth_type determines login method). If no credentials provided, this stage is skipped with status `skipped — no credentials`.

---

### Stage 2: user_registration (Section 4.3.2)

**Objective:** Validate the integrity of the user registration process — check for role manipulation, mass assignment, and validation bypasses.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| RegistrationTester | New | LIGHT | Locates registration endpoints (discovered by info_gathering stage 6 or config_mgmt stage 5). Tests: (1) **Role manipulation** — submit registration with added `role=admin`, `is_admin=1`, `group=administrators` parameters. (2) **Email validation bypass** — register with invalid email formats, disposable email domains, overly long addresses. (3) **Mass assignment** — add unexpected fields to registration payload (`verified=true`, `email_confirmed=1`, `account_status=active`). (4) **Duplicate registration** — attempt to register with Testing User's email, check error message for enumeration (should be generic). (5) **Rate limiting** — rapid registration attempts to test for abuse. Does NOT actually create persistent accounts — tests are validated by response analysis (200 vs 403 vs 422). |

---

### Stage 3: account_provisioning (Section 4.3.3)

**Objective:** Assess admin-side account creation for least-privilege enforcement and logic flaws.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| ProvisioningAuditor | New | LIGHT | Using Tester session, examines administrative account management interfaces (if Tester has admin-level access) or tests for provisioning API endpoints discoverable from info_gathering. Tests: (1) **Least privilege** — can new accounts be created with higher privileges than the creator? (2) **Invite bypass** — if the app uses invite-only registration, can the invite mechanism be bypassed by directly calling the provisioning API? (3) **Bulk provisioning** — can the API be abused to create many accounts rapidly? (4) **Self-privilege escalation** — can Tester modify their own role via the provisioning interface? If Tester lacks admin access, this stage runs in enumeration-only mode — probing for provisioning endpoints without attempting to create accounts. |

---

### Stage 4: account_enumeration (Section 4.3.4)

**Objective:** Determine whether the application leaks information about valid usernames through differential responses.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| EnumerationProber | New | LIGHT | Tests all authentication-related endpoints for username enumeration: (1) **Login form** — submit valid username + wrong password vs invalid username + wrong password. Compare: response body (different error messages?), response time (timing side-channel?), response headers (different cookies set?), HTTP status codes. (2) **Password reset** — submit valid email vs invalid email. Check for differential responses ("email sent" vs "no account found"). (3) **Registration** — submit existing email vs new email. Check for "email already registered" leaks. (4) **API endpoints** — test `/api/users/{username}` or `/api/check-email` if discovered. Timing analysis uses statistical comparison (10 requests each, compare mean response times). Each enumeration vector stored as a Vulnerability record (differential error messages → MEDIUM, timing side-channel → LOW). |

---

### Stage 5: username_policy (Section 4.3.5)

**Objective:** Assess whether username policies prevent predictable or easily guessable accounts.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| UsernamePolicyTester | New | LIGHT | If registration is available, tests username policy enforcement: (1) **Minimum length** — attempt registration with 1-char, 2-char, 3-char usernames. (2) **Predictable patterns** — attempt common usernames: `admin`, `administrator`, `root`, `test`, `user`, `guest`, `demo`, `support`, `info`. (3) **Special characters** — test `admin'--`, `admin<script>`, `admin%00` to check for injection in username field. (4) **Case sensitivity** — test `Admin` vs `admin` vs `ADMIN` to check for case-insensitive collision. (5) **Enumerable sequences** — check if existing users follow sequential patterns (user001, user002). Stores policy weaknesses as Vulnerability records. |

---

# Authentication Worker (4.4)

**Worker Directory:** `workers/authentication/`
**Queue:** `authentication_queue`
**Trigger:** identity_mgmt complete
**Stages:** 10

---

### Stage 1: encrypted_channel (Section 4.4.1)

**Objective:** Verify that credentials are never transmitted over unencrypted channels.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| TlsLoginAuditor | New | LIGHT | (1) Check if login form is served over HTTPS. (2) Check if form action URL uses HTTPS. (3) Check for mixed content on login page (CSS/JS loaded over HTTP could be MitM'd to steal credentials). (4) Test if login endpoint accepts HTTP requests (should redirect to HTTPS or refuse). (5) Check for HTTP→HTTPS upgrade without HSTS (vulnerable to SSL stripping). (6) Verify that API authentication endpoints (token, OAuth) also enforce HTTPS. Uses the traffic proxy opt-in to capture the full login flow for PoC documentation. |

---

### Stage 2: default_credentials (Section 4.4.2)

**Objective:** Test for default, vendor-specific, and commonly used credentials across all login interfaces.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| DefaultCredScanner | New | LIGHT | Tests discovered login endpoints and admin interfaces (from config_mgmt stage 5) with default credential pairs. Credential lists are platform-specific, selected based on framework fingerprint: **Generic:** admin/admin, admin/password, admin/123456, root/root, test/test. **WordPress:** admin/admin. **Tomcat:** tomcat/s3cret, admin/admin, manager/manager. **Jenkins:** admin/admin. **Grafana:** admin/admin. **phpMyAdmin:** root/(empty). **MongoDB:** (no auth test). **Elasticsearch:** (no auth test). **Redis:** (no auth test). Rate-limited: 1 attempt per 3 seconds to avoid lockouts. Stops after first successful login per interface. Each successful default login → CRITICAL Vulnerability. |
| Medusa | Carried (network_worker) | HEAVY | Network-level credential testing for non-HTTP services discovered by config_mgmt stage 1: SSH, FTP, SMB, RDP, MySQL, PostgreSQL, MSSQL. Uses curated credential lists (top 20 per service, not exhaustive brute-force). Rate-limited: 1-2 attempts per second. Stops after 3 consecutive lockouts. Only tests services in scope. Each successful login → CRITICAL Vulnerability. |

---

### Stage 3: lockout_mechanism (Section 4.4.3)

**Objective:** Verify that the application implements effective brute-force protection.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| LockoutTester | New | LIGHT | Progressive failed login testing against the Tester account (not Testing User — we control this account and can unlock it): (1) Send failed logins incrementally (1, 2, 3... up to 20), recording response at each step. (2) Detect lockout threshold (response changes from "invalid password" to "account locked" or CAPTCHA appears). (3) If lockout occurs, measure lockout duration (retry every 30 seconds until unlocked). (4) Test if lockout is IP-based or account-based (retry from different source if possible). (5) Check if CAPTCHA is present and at what threshold. (6) Test if lockout can be bypassed by changing User-Agent, X-Forwarded-For, or using different login endpoints (API vs form). No lockout mechanism → HIGH Vulnerability. Lockout threshold > 20 → MEDIUM. Bypassable lockout → HIGH. |

---

### Stage 4: auth_bypass (Section 4.4.4)

**Objective:** Attempt to reach protected functionality without valid credentials.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| AuthBypassProber | New | LIGHT | (1) **Forceful browsing** — access protected URLs (discovered from authenticated crawl in identity_mgmt stage 1) without any session cookie. Check if content is returned (200) vs redirect to login (302) vs forbidden (403). (2) **Parameter manipulation** — add `isAdmin=true`, `role=admin`, `authenticated=1`, `debug=1` to requests. (3) **Header manipulation** — add `X-Custom-IP-Authorization: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL` headers to bypass path-based auth. (4) **HTTP method switching** — if GET is blocked, try POST, PUT, HEAD. (5) **Path traversal bypass** — `/admin/../admin`, `/./admin`, `/admin/./`, `//admin`, `/admin%20`. Each bypass → CRITICAL Vulnerability. |
| JwtTool | Carried (api_worker) | LIGHT | JWT-specific authentication bypass: (1) **Algorithm confusion** — change `alg` from RS256 to HS256, sign with public key. (2) **None algorithm** — set `alg: "none"`, remove signature. (3) **Key brute-force** — test common secrets (secret, password, 123456, key). (4) **Claim tampering** — modify `sub`, `role`, `admin` claims. (5) **Expired token reuse** — test if expired JWTs are still accepted. (6) **JWK injection** — embed attacker key in JWT header. Only runs if JWT is detected in authentication flow. |
| OauthTesterTool | Carried (api_worker) | LIGHT | OAuth/OIDC flow manipulation: (1) **Redirect URI manipulation** — test open redirect in redirect_uri parameter. (2) **State parameter** — check if CSRF protection via state is enforced. (3) **Scope escalation** — request additional scopes beyond what was granted. (4) **Authorization code replay** — test if codes can be reused. (5) **Token leakage** — check if tokens appear in URL fragments, Referer headers, or browser history. Only runs if OAuth is detected in authentication flow. |

---

### Stage 5: remember_password (Section 4.4.5)

**Objective:** Assess the security of persistent authentication ("remember me") functionality.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| RememberMeTester | New | LIGHT | (1) Enable "remember me" during Tester login, capture the persistent token. (2) **Token entropy** — analyze token randomness (Shannon entropy, character set). (3) **Token storage** — check if stored in cookie vs localStorage (cookies are better — HttpOnly protection). (4) **Token replay after logout** — logout, then replay the remember-me token. Should be invalidated. (5) **Token expiration** — check the cookie's Expires/Max-Age. Flag if > 30 days or no expiration. (6) **Token predictability** — collect multiple tokens, check for sequential or time-based patterns. Weak remember-me → MEDIUM Vulnerability. Replayable after logout → HIGH. |

---

### Stage 6: browser_cache (Section 4.4.6)

**Objective:** Verify that sensitive authenticated pages are not cached by the browser.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CacheWeaknessTester | New | LIGHT | (1) Authenticate as Tester, visit sensitive pages (profile, settings, account). (2) Check response headers: `Cache-Control` should be `no-store` or `no-cache, no-store, must-revalidate`. `Pragma: no-cache` for HTTP/1.0 compatibility. `Expires: 0` or past date. (3) Flag any sensitive page with `Cache-Control: public` or missing cache headers. (4) Test back-button exposure — after logout, check if pressing "back" reveals cached content by analyzing cache headers (actual back-button simulation requires browser context from client_side worker). Missing cache directives on sensitive pages → MEDIUM Vulnerability. |

---

### Stage 7: password_policy (Section 4.4.7)

**Objective:** Assess password complexity requirements and history enforcement.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PasswordPolicyTester | New | LIGHT | Uses Tester account to exercise the password change flow: (1) **Minimum length** — attempt passwords of length 1, 4, 6, 8, 12. Record minimum accepted. (2) **Complexity** — test passwords without uppercase, without digits, without special chars. (3) **Common passwords** — test `password`, `123456`, `qwerty`. Should be rejected. (4) **Password history** — change password to A, then to B, then back to A. Should be rejected if history is enforced. (5) **Maximum length** — test very long passwords (1000+ chars). Should be accepted up to a reasonable limit (not truncated silently). After testing, restores original Tester password. Weak policy (no complexity, min < 8) → MEDIUM Vulnerability. |

---

### Stage 8: security_questions (Section 4.4.8)

**Objective:** Assess the security of knowledge-based authentication questions used in account recovery.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SecurityQuestionAuditor | New | LIGHT | (1) Detect presence of security questions in registration, recovery, or profile settings. (2) If present, assess question quality: **Guessable** — "What is your favorite color?" (limited answer space). **Publicly available** — "What city were you born in?" (social media). **Good** — "What was your first pet's name?" (not publicly available, many possible answers). (3) Test brute-force protection on answer submission. (4) Check if answers are case-sensitive (they shouldn't be for usability, but must still be hashed). (5) Check answer length requirements. Guessable questions without brute-force protection → MEDIUM Vulnerability. |

---

### Stage 9: password_change_reset (Section 4.4.9)

**Objective:** Validate the security of password reset token generation, delivery, and consumption.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| ResetFlowTester | New | LIGHT | (1) **Token entropy** — trigger reset for Tester, capture token from reset link. Analyze randomness. (2) **Token expiration** — wait configurable period (default 15 min), attempt to use token. Should expire within 30 minutes. (3) **Token reuse** — use token, then attempt to reuse it. Should be single-use. (4) **Email enumeration** — submit reset for Testing User's email vs non-existent email. Response should be identical ("if an account exists, a link will be sent"). (5) **Token format** — check if token is guessable (sequential, timestamp-based, short). (6) **Password change without old password** — test if the change-password endpoint requires the current password. (7) **Host header poisoning** — submit reset with manipulated Host header, check if the reset link in email uses the attacker's domain. Uses traffic proxy opt-in for host header manipulation. Predictable/reusable tokens → HIGH Vulnerability. Missing old password requirement → MEDIUM. |

---

### Stage 10: alternative_channel (Section 4.4.10)

**Objective:** Verify that authentication is equally strong across all channels (web, mobile API, legacy endpoints).

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| AlternativeAuthProber | New | LIGHT | (1) Identify alternative authentication endpoints: mobile API (`/api/v1/auth/login` vs `/login`), legacy endpoints (`/v1/login` when current is `/v2/login`), GraphQL mutations (`mutation { login(...) }`). (2) Compare authentication stringency: Does the mobile API enforce lockout? Does the legacy endpoint require CAPTCHA? Does the API enforce rate limiting? (3) Test if the mobile API accepts weaker credentials (shorter passwords, missing MFA). (4) Check if OAuth flows on secondary channels use different scopes or redirect validation. Weaker auth on alternative channel → HIGH Vulnerability (backdoor around primary defenses). |

---

# Authorization Worker (4.5)

**Worker Directory:** `workers/authorization/`
**Queue:** `authorization_queue`
**Trigger:** authentication complete
**Stages:** 4

---

### Stage 1: directory_traversal (Section 4.5.1)

**Objective:** Test if an attacker can access arbitrary files on the server through path manipulation.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PathTraversalTester | New | LIGHT | Identifies all parameters that accept file paths or filenames (from info_gathering stage 6). For each, injects traversal sequences: **Basic:** `../../../etc/passwd`, `..\\..\\..\\Windows\\win.ini`. **Null byte:** `../../../etc/passwd%00.jpg` (truncate extension). **URL encoding:** `%2e%2e%2f`, `%252e%252e%252f` (double encoding). **UTF-8 encoding:** `%c0%ae%c0%ae/` (overlong encoding). **Filter bypass:** `....//`, `..;/`, `..%00/`. Tests both Linux and Windows paths based on server fingerprint. Successful file read → HIGH Vulnerability with PoC showing file contents. |

---

### Stage 2: auth_schema_bypass (Section 4.5.2)

**Objective:** Test horizontal privilege escalation — can user A access user B's resources?

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| HorizontalPrivEscTester | New | LIGHT | Using Tester session, systematically accesses Testing User's resources: (1) Enumerate all endpoints with user-specific parameters (`user_id`, `account`, `profile`, `email`). (2) Replace Tester's identifiers with Testing User's identifiers (username or email per safety policy). (3) Compare responses: 200 with Testing User's data → confirmed IDOR. 403/404 → properly protected. (4) Test across all HTTP methods (GET for data read, PUT/PATCH for data modification — modification is attempted but halted via `on_escalated_access()` if successful). (5) Test mass assignment — send PUT/PATCH with additional fields the Tester shouldn't be able to set. Each successful horizontal access → HIGH Vulnerability. |
| MassAssignTesterTool | Carried (api_worker) | LIGHT | Replays POST/PUT/PATCH requests with extra fields injected: `is_admin`, `role`, `balance`, `verified`, `email_verified`, `permissions`. Tests if the server accepts and persists fields not present in the original form. Each accepted extra field → MEDIUM-HIGH Vulnerability depending on field sensitivity. |

---

### Stage 3: privilege_escalation (Section 4.5.3)

**Objective:** Test vertical privilege escalation — can a low-privilege user access admin-only functions?

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| VerticalPrivEscTester | New | LIGHT | Using Tester session (assumed low-privilege), attempts to access admin-only resources discovered by config_mgmt stage 5 and identity_mgmt stage 1: (1) Direct access to admin URLs with Tester's session cookie. (2) Access admin API endpoints (user management, configuration, reporting). (3) Modify Tester's own role via API (PUT /api/users/me with `role=admin`). (4) Test function-level access control — admin actions (delete user, change settings, export data) with Tester's token. (5) Test by removing authorization headers entirely — some endpoints may fall through to a default "allow" state. Each successful escalation → CRITICAL Vulnerability. If admin access is gained, `on_escalated_access()` is called. |

---

### Stage 4: insecure_direct_object_ref (Section 4.5.4)

**Objective:** Systematic IDOR sweep across all parameterized endpoints.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| IdorTester | Carried (api_worker) | LIGHT | Comprehensive IDOR testing: (1) Enumerate all endpoints with numeric IDs, UUIDs, or sequential identifiers. (2) For each, replace the Tester's object ID with: Testing User's known identifiers, ID ± 1 (sequential guessing), common test IDs (0, 1, -1, 999999). (3) Test across all methods: GET (data read), PUT (data modify), DELETE (data remove — verify via response code only, do not confirm deletion). (4) Test nested resources: `/api/users/{user_id}/orders/{order_id}` — swap user_id while keeping valid order_id. (5) Check for IDOR in file downloads: `/download?file_id=123`. (6) Test GraphQL queries with other users' IDs. Each successful unauthorized access → HIGH-CRITICAL Vulnerability. Escalated access triggers `on_escalated_access()`. |

---

# Session Management Worker (4.6)

**Worker Directory:** `workers/session_mgmt/`
**Queue:** `session_mgmt_queue`
**Trigger:** authentication complete (parallel with authorization)
**Stages:** 9

---

### Stage 1: session_schema (Section 4.6.1)

**Objective:** Assess the quality of session identifier generation — entropy, randomness, predictability.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SessionAnalyzer | New | LIGHT | (1) Collect 20+ session IDs by logging in repeatedly as Tester (logout + login cycle). (2) **Entropy analysis** — calculate Shannon entropy of the session ID character set. Minimum recommended: 64 bits. (3) **Randomness testing** — check for sequential patterns, timestamp components, predictable increments. (4) **Character set** — identify if using hex, base64, alphanumeric. Flag if limited character set reduces entropy. (5) **Length analysis** — session IDs should be ≥ 128 bits (32 hex chars). (6) **Cross-session analysis** — check if any portion of the ID is constant across sessions (indicates structural weakness). Low entropy → HIGH Vulnerability (predictable session IDs enable hijacking). |

---

### Stage 2: cookie_attributes (Section 4.6.2)

**Objective:** Verify that session cookies have proper security attributes.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CookieAuditor | Carried (webapp_worker) | LIGHT | For each cookie set by the application: (1) **Secure flag** — must be set for HTTPS sites. Missing → session sent over HTTP. (2) **HttpOnly flag** — must be set for session cookies. Missing → accessible to JavaScript (XSS can steal it). (3) **SameSite attribute** — should be `Strict` or `Lax`. Missing or `None` without Secure → CSRF vulnerability. (4) **Domain scope** — should not be set to parent domain (`.example.com` gives all subdomains access). (5) **Path scope** — should be restrictive (not `/` if only needed for `/app`). (6) **Expires/Max-Age** — session cookies should not have long expiry. (7) **Cookie name** — should not reveal technology (rename `PHPSESSID` etc. to generic name). Each missing attribute → Vulnerability with severity based on impact. |

---

### Stage 3: session_fixation (Section 4.6.3)

**Objective:** Test if the application reuses session IDs across authentication boundaries.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| FixationTester | New | LIGHT | (1) Visit the application unauthenticated, capture the session ID. (2) Authenticate as Tester with the same browser session. (3) Compare session ID before and after login. If the ID is unchanged → SESSION FIXATION confirmed (HIGH Vulnerability). (4) Test fixation via URL — if the app accepts session IDs in URL parameters (`;jsessionid=XXX`), set a known ID and authenticate. (5) Test fixation via cookie injection — set a custom session cookie, authenticate, check if the app adopts it. (6) Test if logout generates a new session ID (it should). Uses traffic proxy opt-in to capture the full authentication flow with before/after session IDs for PoC. |

---

### Stage 4: exposed_session_variables (Section 4.6.4)

**Objective:** Identify if session identifiers are leaked through URLs, logs, or other channels.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SessionExposureScanner | New | LIGHT | (1) **URL leakage** — check if session ID appears in any URL (query parameter, path segment). Examine Referer header sent to external resources — session ID in Referer leaks to third parties. (2) **JavaScript exposure** — check if `document.cookie` returns session cookie (should be HttpOnly). Check if session ID is stored in `window.sessionStorage` or `window.localStorage`. (3) **Error message leakage** — trigger errors and check if session data appears in error responses. (4) **Log exposure** — check if any accessible log files (from config_mgmt stage 4) contain session IDs. (5) **HTML source** — check if session ID is embedded in hidden form fields or JavaScript variables. Each exposure vector → MEDIUM-HIGH Vulnerability. |

---

### Stage 5: csrf (Section 4.6.5)

**Objective:** Test if the application can distinguish between legitimate requests and those forged by a malicious site.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CsrfTester | New | LIGHT | For each state-changing endpoint (POST, PUT, DELETE, PATCH): (1) **Missing token** — replay the request without anti-CSRF token. If it succeeds → CSRF vulnerability. (2) **Token reuse** — use a token from a different session. Should be rejected. (3) **Token from different form** — use a CSRF token from form A in form B. Should be rejected (per-form tokens). (4) **Cross-origin test** — send the request with `Origin: https://evil.com`. Check if the server validates Origin/Referer. (5) **JSON CSRF** — for API endpoints accepting JSON, test if `Content-Type: application/json` is enforced or if `text/plain` is accepted (Flash-based CSRF). (6) **Method override** — test if `X-HTTP-Method-Override: DELETE` bypasses CSRF on GET requests. Uses traffic proxy opt-in to strip CSRF tokens from requests. Each successful CSRF → MEDIUM-HIGH Vulnerability (severity based on action impact — password change CSRF is CRITICAL). |

---

### Stage 6: logout (Section 4.6.6)

**Objective:** Verify that logout properly invalidates the session server-side.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| LogoutTester | New | LIGHT | (1) Authenticate as Tester, capture session token. (2) Logout. (3) Replay the captured session token — send an authenticated request with the old token. If it succeeds → server-side session still valid (HIGH Vulnerability). (4) Check if logout clears all session cookies (not just the primary one). (5) Check if logout invalidates remember-me tokens. (6) Test if multiple active sessions are all invalidated on logout (or just the current one — "logout from all devices" feature). (7) Test if the application redirect after logout is to a safe page (not a redirect loop or error). Incomplete session invalidation → HIGH Vulnerability (session reuse after logout). |

---

### Stage 7: session_timeout (Section 4.6.7)

**Objective:** Verify that idle and absolute session timeouts are enforced.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| TimeoutTester | New | LIGHT | (1) Authenticate as Tester, capture session token. (2) **Idle timeout** — wait for configurable period (default: test at 15 min, 30 min intervals), then attempt to use the session. Record when it expires. (3) **Absolute timeout** — continuously use the session (preventing idle timeout) and check if it expires after a maximum duration. (4) Compare actual timeouts against security best practices: session timeout should be ≤ 30 minutes for sensitive applications, ≤ 8 hours for low-sensitivity. (5) Check if timeout behavior is consistent across endpoints (some may not check session validity). No idle timeout → MEDIUM Vulnerability. Very long timeout (> 24 hours) → LOW. Note: This stage may take 30-60 minutes to complete due to timeout waiting. Pipeline accounts for this in stage timing estimates. |

---

### Stage 8: session_puzzling (Section 4.6.8)

**Objective:** Test if session variables from one application flow carry unintended state into another.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SessionPuzzlingTester | New | LIGHT | (1) Initiate a password reset flow — this often sets session variables (`reset_user`, `reset_email`, `verified`). (2) Without completing the reset, navigate to authenticated areas. Check if the reset session variables grant access or bypass authentication. (3) Test cross-flow contamination: start a purchase flow (sets `cart`, `payment_pending`), then access profile — do purchase session vars affect profile behavior? (4) Test registration flow → authenticated area transition — does partially completing registration grant session attributes that carry into other flows? (5) Test multi-step form → different multi-step form — do step indicators from form A affect form B? Each cross-flow contamination → MEDIUM-HIGH Vulnerability. |

---

### Stage 9: session_hijacking (Section 4.6.9)

**Objective:** Assess the overall vulnerability of session tokens to theft via various vectors.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| HijackingAuditor | New | LIGHT | Aggregation stage — synthesizes findings from prior stages and other workers to assess hijacking risk: (1) **Network sniffing** — is the session transmitted over HTTP? (from stage 2 Secure flag + authentication stage 1). (2) **XSS theft** — is the session accessible to JavaScript? (from stage 2 HttpOnly flag + client_side worker DOM XSS findings). (3) **Cross-site leakage** — does the session appear in Referer headers to external sites? (from stage 4). (4) **Predictability** — can the session be guessed? (from stage 1 entropy analysis). (5) **Fixation** — can the session be set by an attacker? (from stage 3). Produces a composite hijacking risk assessment as an Observation record, and flags the most critical attack vector as the primary Vulnerability. If any vector confirms session theft is feasible, calls `on_escalated_access()` with the session token and attack method. |

---

## Shared Patterns Across All Four Workers

### Credential Usage

All four workers call `get_tester_session()` for authenticated requests. The session is cached across stages — the worker authenticates once at pipeline start and reuses the session until it expires (with automatic re-authentication).

### Testing User Targeting

Stages that need a victim identity (authorization stages 2-4, session_mgmt stages 3, 5) call `get_target_user()` to get the Testing User's identifiers. `validate_target_user()` is called before every IDOR/targeting request.

### Escalated Access

All four workers have `on_escalated_access()` available. It's most likely to trigger in:
- authorization stage 2 (horizontal priv esc)
- authorization stage 3 (vertical priv esc)
- authorization stage 4 (IDOR)
- session_mgmt stage 9 (session hijacking)

### Skipping Stages

If credentials are not provided in the campaign config, identity_mgmt through business_logic are skipped entirely with status `skipped — no credentials`. This is recorded in `job_state` so the dependency graph knows to proceed (treating skipped as "complete" for downstream triggers).
