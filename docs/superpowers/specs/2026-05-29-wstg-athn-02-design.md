# WSTG-ATHN-02: Testing for Default Credentials — Design Spec

**Date:** 2026-05-29  
**WSTG reference:** [WSTG-ATHN-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)  
**Worker:** `authentication`  
**Stage:** `default_credentials` (index 1 in STAGES, between `credentials_transport` and `lockout_mechanism`)

---

## 1. Objective

Replace the existing pure-Python `DefaultCredentialTester` (embedded httpx script, 23 hardcoded credential pairs) with a production-quality implementation that:

- Runs Nuclei's `default-logins` template suite (community + custom) as the primary engine
- Falls back to Hydra for paths/apps not covered by any Nuclei template
- Reads target URLs from the DB (admin_interface assets set by config_mgmt) with a self-discovery fallback
- Exposes all rate-limit, delay, and proxy-pool settings through the existing dashboard SettingsDrawer
- Applies strict safety controls to prevent triggering account lockouts or IP bans

---

## 2. Architecture

### 2.1 Docker image changes (`docker/Dockerfile.auth`)

Convert to a multi-stage build (mirrors `Dockerfile.config_mgmt`):

**Stage 1 — Go builder:**
```dockerfile
FROM golang:1.24-bookworm AS go-builder
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Stage 2 — Runtime:**
```dockerfile
FROM python:3.10-slim-bookworm
RUN apt-get install -y hydra wget
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei

# Bake community templates at build time
RUN nuclei -update-templates -ud /nuclei-templates/community || true

# Custom templates shipped with the worker
COPY workers/authentication/nuclei-templates/ /nuclei-templates/custom/

# Trimmed SecLists credential pair files
COPY workers/authentication/wordlists/ /wordlists/auth/
```

### 2.2 New repository directories

```
workers/authentication/
  nuclei-templates/       ← copy from C:\Users\dat1k\Projects\default-login-templates\
  wordlists/
    users.txt             ← top-20 common default usernames from SecLists
    passes.txt            ← top-20 common default passwords from SecLists
    pairs_top10.txt       ← hydra-format colon-delimited top-10 pairs (Hydra -C flag)
    pairs_top3.txt        ← top-3 pairs used when lockout threshold ≤5 is confirmed
```

The `pairs_top10.txt` content (for Hydra `-C`):
```
admin:admin
admin:password
admin:admin123
admin:123456
root:root
root:toor
tomcat:tomcat
manager:manager
admin:
guest:guest
```

### 2.3 Tool file

`workers/authentication/tools/default_credential_tester.py` — fully replaced.

The class overrides `execute()` directly (same pattern as `config_mgmt/tools/default_credential_tester.py`) rather than relying on `build_command()` / `parse_output()`. The abstract contract is satisfied with stub implementations.

---

## 3. Execution Flow

```
execute(target, scope_manager, target_id, container_name, credentials)
│
├─ 1. check_cooldown → return early if within 24 h
├─ 2. acquire HEAVY semaphore
├─ 3. emit TOOL_PROGRESS(0%)
│
├─ 4. Load settings from config dir
│     shared/config/{target_id}/rate_limits.json   → pps (default 10)
│     shared/config/{target_id}/custom_headers.json → dict of extra headers
│     shared/config/{target_id}/default_creds.json  → proxy_pool list
│
├─ 5. Discover target URLs
│     a. Query DB: Asset(asset_type="admin_interface", target_id=N)
│     b. If none: probe DEFAULT_PATHS with a single httpx GET per path (timeout=5s)
│        Accept paths returning 200 or 401 (Basic Auth challenge)
│
├─ 6. CAPTCHA pre-filter
│     For each URL, GET and check response for reCAPTCHA / hCaptcha / turnstile markers
│     → skip URL for both Nuclei and Hydra if CAPTCHA detected
│
├─ 7. Nuclei phase
│     Build a temp URL list file
│     Run: nuclei -l {urls_file}
│                 -t /nuclei-templates/community/http/default-logins/
│                 -t /nuclei-templates/custom/
│                 -rate-limit {pps}
│                 -H "X-Forwarded-For: {rotated_ip}"
│                 [-H "CustomKey: val" ...]  ← from custom_headers.json
│                 -timeout 10 -retries 1 -silent -json -no-interactsh
│     Parse JSONL → record template-id, matched-at, extracted credentials
│     Track which URLs had at least one Nuclei template match (even if no hit)
│
├─ 8. Hydra phase (conservative)
│     Only for URLs with NO Nuclei template match
│     For each such URL:
│       a. Check DB for existing lockout_tester Observation for this target
│          → if lockout at ≤5 attempts, use pairs_top3.txt (3 pairs only)
│          → otherwise use pairs_top10.txt
│       b. Detect auth type: GET the URL, check for WWW-Authenticate: Basic header
│          → Basic Auth: module=http-get
│          → Form-based: module=http-form-post with field params
│       c. Run hydra:
│            -C /wordlists/auth/pairs_top{N}.txt
│            -t 1                        (single thread)
│            -w {hydra_wait}             (default 15 s, min 5 s)
│            -f                          (stop at first hit)
│            -H "X-Forwarded-For: {ip}" (cycled from proxy_pool)
│            [-H "CustomKey: val" ...]
│       d. After each attempt: check for 429 / lockout signals → abort immediately
│
├─ 9. Merge all results → save Observations
│     severity=critical for credential hits
│     severity=info for summary (always saved)
│
├─ 10. Update job_state.last_tool_executed
└─ 11. emit TOOL_PROGRESS(100%)
```

---

## 4. Rate Limiting & IP Rotation

| Control | JSON key | Default | Notes |
|---------|----------|---------|-------|
| Nuclei rate limit | `rate_limits.json → pps` | 10 req/s | Passed as `nuclei -rate-limit` |
| Hydra inter-attempt delay | `default_creds.json → hydra_wait_secs` | 15 s | Passed as `hydra -w` |
| IP rotation pool | `default_creds.json → proxy_pool` | `[]` | X-Forwarded-For rotation list |
| Custom request headers | `custom_headers.json` | `{}` | Forwarded to both Nuclei and Hydra |

IP rotation strategy: index into the proxy_pool list using `attempt_count % len(pool)`. If the pool is empty, no X-Forwarded-For header is added.

---

## 5. Hydra Safety Controls

1. **Credential cap**: Top 10 pairs maximum (3 if lockout mechanism is confirmed at ≤5 attempts).
2. **Single thread**: `-t 1` always. Not configurable.
3. **Conservative delay**: Default 15 seconds between attempts. Dashboard can increase this, not decrease below 5 s.
4. **Early abort signals**: After each Hydra attempt, inspect stdout for:
   - HTTP 429
   - `Retry-After` header
   - Response body containing: "too many", "account locked", "temporarily blocked", "cooldown"
   → Abort all remaining Hydra attempts for this URL.
5. **CAPTCHA skip**: Any URL with CAPTCHA markers detected in step 6 is excluded.
6. **Stop-at-first**: `-f` flag always set.

---

## 6. Dashboard Settings Integration

### 6.1 New `DefaultCredsSettings` type (`dashboard/src/types/schema.ts`)

```typescript
export interface DefaultCredsSettings {
  proxy_pool?: string[];        // X-Forwarded-For IPs for rotation
  hydra_wait_secs?: number;     // Hydra inter-attempt delay (min 5)
  nuclei_rate_limit?: number;   // Nuclei req/s override
}
```

Add `default_creds?: DefaultCredsSettings` to `TargetProfile`.

### 6.2 SettingsDrawer section

New "Default Credentials" accordion in `SettingsDrawer.tsx`:
- **Proxy pool** — textarea, one IP per line, mapped to `proxy_pool`
- **Hydra delay (s)** — number input (min 5), mapped to `hydra_wait_secs`
- **Nuclei rate limit (req/s)** — number input, mapped to `nuclei_rate_limit`

Saved via existing `PATCH /api/v1/targets/{id}/profile` route under `default_creds` key.

### 6.3 Orchestrator model + config write (`orchestrator/main.py`)

`TargetProfileUpdate` gains `default_creds: Optional[dict] = None`.

Profile handler writes:
```python
if body.default_creds is not None:
    profile["default_creds"] = body.default_creds
(config_dir / "default_creds.json").write_text(json.dumps(profile.get("default_creds", {}), indent=2))
```

---

## 7. Data Persistence

All findings land in the existing `Observation` model — no new tables.

```python
Observation(
    target_id=target_id,
    observation_type="authentication",
    source_tool="default_credential_tester",
    title="Default credentials accepted: admin/admin @ https://example.com/wp-admin",
    severity="critical",   # on a hit; "info" for the clean-pass summary
    data={
        "url": str,
        "username": str,
        "password": str,
        "auth_type": "form" | "basic",
        "template_id": str | None,   # Nuclei template ID, or None for Hydra hits
        "framework": str | None,
    }
)
```

One `info`-severity summary observation is always saved so the dashboard shows stage activity regardless of findings.

---

## 8. Three-layer Coherence

No new pipeline stage is added — `default_credentials` already exists in:
- `workers/authentication/pipeline.py` ✓
- `shared/lib_webbh/playbooks.py` → `"authentication": ["credentials_transport", "default_credentials", ...]` ✓
- `dashboard/src/lib/worker-stages.ts` → verify `default_credentials` is listed ✓

No coherence change needed; only the tool implementation changes.

---

## 9. Testing

### Unit tests (`tests/unit/authentication/test_default_credential_tester.py`)
- `test_parse_nuclei_output_hit` — fixture JSONL with a matched template → Observation dict
- `test_parse_nuclei_output_no_hit` — fixture JSONL with no match → empty list
- `test_parse_hydra_output_hit` — fixture Hydra stdout line → Observation dict
- `test_is_captcha_protected` — response bodies with/without CAPTCHA markers
- `test_select_hydra_pairs_lockout` — when lockout_obs present at ≤5 → returns ≤3 pairs

### E2E (`tests/e2e/test_authentication.py`)
- Stage `default_credentials` listed in `STAGE_ASSERTIONS`
- Assertion: at least one `Observation(source_tool="default_credential_tester")` exists (the info summary)
- No timeout on the stage (DVWA credentials succeed quickly via Nuclei template)

### DVWA positive case
The custom template `dvwa-default-login.yaml` covers DVWA (admin/password). Running against a DVWA instance in the test stack provides a confirmed true-positive path.

---

## 10. Files Changed

| File | Change |
|------|--------|
| `docker/Dockerfile.auth` | Multi-stage build; add Nuclei + Hydra; bake templates + wordlists |
| `workers/authentication/nuclei-templates/` | New dir — copy from local default-login-templates |
| `workers/authentication/wordlists/` | New dir — pairs_top10.txt, users.txt, passes.txt |
| `workers/authentication/tools/default_credential_tester.py` | Full replacement |
| `orchestrator/main.py` | Add `default_creds` to `TargetProfileUpdate`; write `default_creds.json` |
| `dashboard/src/types/schema.ts` | Add `DefaultCredsSettings`; extend `TargetProfile` |
| `dashboard/src/components/c2/SettingsDrawer.tsx` | New Default Credentials accordion section |
| `tests/unit/authentication/test_default_credential_tester.py` | New unit test file |
| `tests/e2e/test_authentication.py` | Add `default_credentials` stage assertion |
