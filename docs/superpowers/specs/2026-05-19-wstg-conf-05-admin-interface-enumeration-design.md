# WSTG-CONF-05: Admin Interface Enumeration — Design Spec

**Date:** 2026-05-19
**Stage:** `admin_interface_enumeration` (new, pipeline index 5)
**Worker:** `config_mgmt`
**OWASP ref:** WSTG-CONF-05 — Enumerate Infrastructure and Application Admin Interfaces
**Tool files:** `workers/config_mgmt/tools/admin_interface_enumerator.py`, `workers/config_mgmt/tools/admin_param_tamperer.py`

---

## Problem Statement

WSTG-CONF-05 has no dedicated pipeline stage. The `AdminInterfaceFinder` tool in `network_config` (CONF-01) does basic path probing and port scanning to feed `DefaultCredentialTester`, but it does not implement the full CONF-05 methodology:

- No external wordlist — hardcoded ~30 paths vs. a quality wordlist
- No platform-aware path injection using `PlatformFingerprinter` results
- No HTML source link mining
- No parameter tampering
- No auth-header fingerprinting
- Uses inline Python subprocess (anti-pattern replaced in CONF-04)
- Findings not tagged `section_id = "WSTG-CONF-05"`

Additionally, `api_discovery` in `worker-stages.ts` is incorrectly tagged `WSTG-CONF-05`. WSTG-CONF-05 is Admin Interface Enumeration; API discovery maps to `WSTG-INFO-06`.

---

## Goals

- Full WSTG-CONF-05 compliance: wordlist probing, platform-aware injection, HTML link mining, auth-header fingerprinting, parameter tampering
- Dedicated `admin_interface_enumeration` pipeline stage after `backup_files`
- `AdminInterfaceFinder` in `network_config` unchanged — it continues to feed `DefaultCredentialTester`
- Fix `api_discovery` sectionId in `worker-stages.ts`
- Three-layer coherence maintained (pipeline + playbooks + dashboard in same commit)

---

## Architecture

```
config_mgmt pipeline (after this change)
──────────────────────────────────────────────────────────────
 network_config           [NetworkConfigTester,               CONF-01 (unchanged)
                           AdminInterfaceFinder]
 network_config_cred_test [DefaultCredentialTester]           CONF-01 (unchanged)
 platform_config          [PlatformFingerprinter]             CONF-02 (unchanged)
 file_extension_handling  [FileExtensionTester]               CONF-03 (unchanged)
 backup_files             [BackupFileFinder, FfufTool]        CONF-04 (unchanged)
 admin_interface_enum     [AdminInterfaceEnumerator,          CONF-05 ← NEW
                           AdminParamTamperer]
 api_discovery            [ApiDiscoveryTool]                  WSTG-INFO-06 (sectionId fix)
 http_methods             [HttpMethodTester]                  CONF-06
 hsts_testing             [HstsTester]                        CONF-07
 rpc_testing              [RpcTester]                         CONF-08
 file_inclusion           [FileInclusionTester]               CONF-09
 subdomain_takeover       [SubdomainTakeoverChecker]          CONF-10
 cloud_storage            [CloudStorageAuditor]               CONF-11
──────────────────────────────────────────────────────────────
```

The new stage is placed after `platform_config` so `AdminInterfaceEnumerator` can read `PlatformFingerprinter` DB results for platform-aware path injection.

Both tools run concurrently via `asyncio.gather` in `pipeline._run_stage()`, mirroring the `backup_files` pattern.

---

## Tool 1: `AdminInterfaceEnumerator`

**File:** `workers/config_mgmt/tools/admin_interface_enumerator.py`

Overrides `execute()` entirely. `build_command` and `parse_output` are ABC stubs raising `NotImplementedError` — they satisfy the contract but are never called.

### Lifecycle

```
execute(target, scope_manager, target_id, container_name, headers)
 ├─ check_cooldown()                    → early return if within cooldown
 ├─ acquire semaphore (HEAVY)
 ├─ emit TOOL_PROGRESS: started
 │
 ├─ [Phase 0 — DB + wordlist reads]
 │   ├─ SELECT asset_value FROM assets WHERE asset_type = 'platform_fingerprint'
 │   │   AND target_id = :tid → build platform-specific path supplement
 │   ├─ Load /wordlists/admin-panels.txt
 │   └─ Merge and deduplicate paths
 │
 ├─ [Phase 1 — Wordlist path probing (asyncio.Semaphore(20))]
 │   └─ HEAD each path (fallback GET on 405)
 │       200             → vulnerability (admin_interface_exposed)
 │       401 / 403       → observation (admin_access_denied)
 │       301/302/307/308 → observation (admin_redirect)
 │
 ├─ [Phase 2 — HTML link mining]
 │   ├─ GET / and GET /index
 │   ├─ Parse href/src/action with BeautifulSoup
 │   ├─ Filter by admin keywords (see below)
 │   └─ Probe each matched link → same routing as Phase 1
 │
 ├─ [Phase 3 — Auth-header fingerprinting]
 │   └─ For every 401 seen in Phases 1–2:
 │       parse WWW-Authenticate → record realm as observation (auth_realm)
 │
 ├─ persist via _process_vulnerability() / _process_observation()
 ├─ update job_state.last_tool_executed
 ├─ emit TOOL_PROGRESS: finished
 └─ return {found, in_scope, new, skipped_cooldown}
```

### Platform Path Injection

If `platform_fingerprint` assets are present in the DB, append these paths to the wordlist:

| Fingerprint keyword | Paths injected |
|---|---|
| `wordpress` | `/wp-admin`, `/wp-login.php`, `/wp-admin/admin-ajax.php` |
| `joomla` | `/administrator/`, `/administrator/index.php` |
| `django` | `/admin/`, `/django-admin/` |
| `laravel` | `/admin`, `/horizon`, `/telescope` |
| `spring` / `actuator` | `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/metrics` |
| `tomcat` | `/manager/html`, `/host-manager/html` |
| `jenkins` | `/jenkins`, `/blue/organizations/jenkins` |
| `kibana` | `/kibana`, `/app/kibana` |

### HTML Link Mining Keywords

```
admin, administrator, manage, manager, control, console, panel,
backend, backoffice, maintenance, setup, config, configure,
cpanel, webmin, plesk, dashboard
```

### Severity Classification

| Condition | Severity | Type |
|---|---|---|
| HTTP 200, no `<input type="password">` in body | `high` | vulnerability — unauthenticated admin access |
| HTTP 200, login form present | `medium` | vulnerability — admin interface exposed |
| HTTP 401 / 403 | `low` | observation — `admin_access_denied` |
| Redirect from admin path | `info` | observation — `admin_redirect` |
| Admin link found in HTML source | `info` | observation — `admin_link` |
| WWW-Authenticate realm discovered | `info` | observation — `auth_realm` |

`section_id = "WSTG-CONF-05"` on every vulnerability row. `worker_type = "config_mgmt"` on all rows.

### HTTP Client

- `httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10, headers=headers or {})`
- `follow_redirects=False` — a redirect from an admin path is itself informational
- `asyncio.Semaphore(20)` caps concurrent requests
- Per-request `httpx.RequestError` silently swallowed

### Weight

`HEAVY` — large wordlist, concurrent HTTP, BeautifulSoup parsing.

---

## Tool 2: `AdminParamTamperer`

**File:** `workers/config_mgmt/tools/admin_param_tamperer.py`

Also overrides `execute()`. `build_command` and `parse_output` raise `NotImplementedError`.

If Phase 0 returns zero URLs, the tool exits immediately with `{"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}`.

### Lifecycle

```
execute(target, scope_manager, target_id, container_name, headers)
 ├─ check_cooldown()                    → early return if within cooldown
 ├─ acquire semaphore (LIGHT)
 ├─ emit TOOL_PROGRESS: started
 │
 ├─ [Phase 0 — DB reads]
 │   └─ SELECT asset_value, tech FROM assets
 │          WHERE asset_type IN ('admin_interface', 'admin_redirect')
 │          AND source_tool IN ('admin_interface_finder',
 │                              'admin_interface_enumerator')
 │          AND target_id = :tid
 │      → URL list; exit early if empty
 │
 ├─ [Phase 1 — Per-URL analysis (asyncio.Semaphore(10))]
 │   For each URL:
 │   ├─ GET URL → baseline (status, content_length, body)
 │   ├─ Parse hidden inputs: <input type="hidden" name=? value=?>
 │   ├─ Parse Set-Cookie headers → extract name=value pairs
 │   ├─ Filter suspicious params/cookies by ADMIN_PARAM_PATTERNS
 │   └─ For each suspicious param → probe with FLIP_VALUES
 │       compare against baseline → Phase 2
 │
 └─ [Phase 2 — Response comparison]
     ├─ Status 403/302 → 200              → critical vulnerability
     ├─ Status unchanged + admin keywords → high vulnerability
     └─ Content-length change > 20%       → medium vulnerability
```

### Suspicious Parameter Patterns

```python
ADMIN_PARAM_PATTERNS = [
    "admin", "useradmin", "is_admin", "isadmin", "administrator",
    "role", "user_type", "usertype", "access", "privilege", "level",
    "debug", "test", "dev", "development", "staff", "superuser",
    "su", "root", "authorized", "auth", "authenticated",
]
```

### Flip Values

```python
FLIP_MAP = {
    "0": "1", "false": "true", "no": "yes",
    "user": "admin", "guest": "admin", "readonly": "admin",
}
```

For unrecognised values, probe with `"admin"` and `"1"`.

### Admin Keywords (body comparison)

```
dashboard, panel, settings, users, configuration, logout, welcome,
administrator, manage, control
```

### Severity Classification

| Condition | Severity | Type |
|---|---|---|
| Status bypassed (403/302 → 200) after param flip | `critical` | vulnerability — `parameter_tampering_bypass` |
| Admin keywords appear in body after flip | `high` | vulnerability — `parameter_tampering_escalation` |
| Response body length changes > 20% | `medium` | vulnerability — `parameter_tampering_indicator` |

`section_id = "WSTG-CONF-05"` on every vulnerability row. `worker_type = "config_mgmt"`.

### Weight

`LIGHT` — pure async httpx, no subprocess.

---

## Wordlist

**Source:** Curated subset of SecLists `Discovery/Web-Content/AdminPanels.txt` (~800 entries), committed to the repo.

**Location in repo:** `workers/config_mgmt/wordlists/admin-panels.txt`

**Location in container:** `/wordlists/admin-panels.txt`

**Dockerfile change:** `docker/Dockerfile.config_mgmt` adds:
```dockerfile
COPY workers/config_mgmt/wordlists/ /wordlists/
```

No internet required at image build time.

---

## Three-Layer Sync

All three files updated in the same commit per the CLAUDE.md coherence rule.

### `workers/config_mgmt/pipeline.py`

```python
STAGES = [
    Stage("network_config",                [NetworkConfigTester, AdminInterfaceFinder]),
    Stage("network_config_cred_test",      [DefaultCredentialTester]),
    Stage("platform_config",               [PlatformFingerprinter]),
    Stage("file_extension_handling",       [FileExtensionTester]),
    Stage("backup_files",                  [BackupFileFinder, FfufTool]),
    Stage("admin_interface_enumeration",   [AdminInterfaceEnumerator, AdminParamTamperer]),  # NEW
    Stage("api_discovery",                 [ApiDiscoveryTool]),
    Stage("http_methods",                  [HttpMethodTester]),
    Stage("hsts_testing",                  [HstsTester]),
    Stage("rpc_testing",                   [RpcTester]),
    Stage("file_inclusion",                [FileInclusionTester]),
    Stage("subdomain_takeover",            [SubdomainTakeoverChecker]),
    Stage("cloud_storage",                 [CloudStorageAuditor]),
]
```

### `shared/lib_webbh/playbooks.py`

```python
"config_mgmt": [
    "network_config",
    "network_config_cred_test",
    "platform_config",
    "file_extension_handling",
    "backup_files",
    "admin_interface_enumeration",   # NEW
    "api_discovery",
    "http_methods",
    "hsts_testing",
    "rpc_testing",
    "file_inclusion",
    "subdomain_takeover",
    "cloud_storage",
],
```

### `dashboard/src/lib/worker-stages.ts`

```typescript
config_mgmt: [
  { id: "1",  name: "Network Configuration",       stageName: "network_config",                sectionId: "WSTG-CONF-01" },
  { id: "1b", name: "Credential Testing",           stageName: "network_config_cred_test",      sectionId: "WSTG-CONF-01" },
  { id: "2",  name: "Platform Configuration",       stageName: "platform_config",               sectionId: "WSTG-CONF-02" },
  { id: "3",  name: "File Extension Handling",      stageName: "file_extension_handling",       sectionId: "WSTG-CONF-03" },
  { id: "4",  name: "Backup Files",                 stageName: "backup_files",                  sectionId: "WSTG-CONF-04" },
  { id: "5",  name: "Admin Interface Enumeration",  stageName: "admin_interface_enumeration",   sectionId: "WSTG-CONF-05" },  // NEW
  { id: "6",  name: "API Discovery",                stageName: "api_discovery",                 sectionId: "WSTG-INFO-06" },  // sectionId fix
  { id: "7",  name: "HTTP Methods",                 stageName: "http_methods",                  sectionId: "WSTG-CONF-06" },
  { id: "8",  name: "HTTP Strict Transport Security", stageName: "hsts_testing",                sectionId: "WSTG-CONF-07" },
  { id: "9",  name: "RPC Testing",                  stageName: "rpc_testing",                   sectionId: "WSTG-CONF-08" },
  { id: "10", name: "File Inclusion",               stageName: "file_inclusion",                sectionId: "WSTG-CONF-09" },
  { id: "11", name: "Subdomain Takeover",           stageName: "subdomain_takeover",            sectionId: "WSTG-CONF-10" },
  { id: "12", name: "Cloud Storage",                stageName: "cloud_storage",                 sectionId: "WSTG-CONF-11" },
],
```

---

## Concurrency Changes

Add to `TOOL_WEIGHTS` in `workers/config_mgmt/concurrency.py`:

```python
"admin_interface_enumerator": WeightClass.HEAVY,
"admin_param_tamperer":       WeightClass.LIGHT,
```

---

## Files Changed

| File | Change |
|---|---|
| `workers/config_mgmt/tools/admin_interface_enumerator.py` | New |
| `workers/config_mgmt/tools/admin_param_tamperer.py` | New |
| `workers/config_mgmt/tools/__init__.py` | Add `AdminInterfaceEnumerator`, `AdminParamTamperer` imports |
| `workers/config_mgmt/concurrency.py` | Add two `TOOL_WEIGHTS` entries |
| `workers/config_mgmt/pipeline.py` | Add `admin_interface_enumeration` stage |
| `shared/lib_webbh/playbooks.py` | Add `"admin_interface_enumeration"` to config_mgmt list |
| `dashboard/src/lib/worker-stages.ts` | Add stage entry; fix `api_discovery` sectionId; renumber ids 6–12 |
| `workers/config_mgmt/wordlists/admin-panels.txt` | New — curated ~800-path SecLists subset |
| `docker/Dockerfile.config_mgmt` | Add `COPY workers/config_mgmt/wordlists/ /wordlists/` |

No changes to `AdminInterfaceFinder`, `NetworkConfigTester`, `DefaultCredentialTester`, or any other existing tool.

---

## Out of Scope

- Changes to any worker other than `config_mgmt`
- Brute-force credential testing on discovered interfaces (handled by `DefaultCredentialTester` in CONF-01)
- Port-level service enumeration (handled by `AdminInterfaceFinder` nmap scan in CONF-01)
- Non-HTTP admin interface exploitation
- Modifications to the existing `AdminInterfaceFinder` tool
