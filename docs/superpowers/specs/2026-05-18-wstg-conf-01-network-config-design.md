# WSTG-CONF-01 — Network Infrastructure Configuration Stage Rebuild

**Date:** 2026-05-18
**Worker:** `config_mgmt`
**Stage(s) affected:** `network_config` (stage 1), new `network_config_cred_test` (stage 1b)
**Guide reference:** WSTG-CONF-01 — Test Network Infrastructure Configuration

---

## Problem Statement

The current `network_config` stage implements only a shallow slice of WSTG-CONF-01:

- Probes 17 HTTP admin paths and reports 200/redirect responses
- Checks for CORS wildcard or echo-origin headers

It is missing all three WSTG-CONF-01 pillars:

1. **Known server vulnerabilities** — no version extraction, no CVE lookup
2. **Administrative tools review** — no non-HTTP service discovery (FTP/WebDAV/NFS/SMB), no default credential testing
3. **Infrastructure mapping** — no port enumeration, no structured service inventory

The CORS check does not belong in CONF-01 (belongs in CONF-10 / HTTP headers). It will be removed from this stage.

---

## Goals

- Full letter-of-the-guide WSTG-CONF-01 compliance
- Three pillars covered: server CVE detection, admin interface discovery (HTTP + non-HTTP), default credential testing
- Respect the three-layer coherence rule (pipeline.py + playbooks.py + worker-stages.ts in sync)
- Credential testing strictly rate-limited to avoid detection and stay within scope

---

## Architecture

### Stage split

The dependency between admin interface discovery and credential testing requires sequential execution. Two stages replace the current one:

| Stage name | Tools | Pillar |
|------------|-------|--------|
| `network_config` | `NetworkConfigTester`, `AdminInterfaceFinder` | Server CVE detection + admin/service discovery |
| `network_config_cred_test` | `DefaultCredentialTester` | Default credential validation on discovered admin interfaces |

Both stages remain within the `config_mgmt` worker. No new worker is introduced.

---

## Tool Specifications

### 1. `NetworkConfigTester` (refactored)

**File:** `workers/config_mgmt/tools/network_config_tester.py`

**Responsibility:** Extract server/framework version strings from HTTP response headers and cross-reference against the NVD REST API.

**Implementation:**

- Send HTTP HEAD (fallback GET) to the target URL
- Extract headers: `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, `X-Runtime`, `X-Served-By`
- Parse product name and version from each header value using regex (e.g. `Apache/2.4.49` → product=`apache`, version=`2.4.49`)
- For each detected product+version, query:
  ```
  GET https://services.nvd.nist.gov/rest/json/cves/2.0
      ?keywordSearch=<product>+<version>&resultsPerPage=10
  ```
- For each CVE returned with `baseScore >= 7.0`: emit a `vulnerability` dict
- For each CVE with `baseScore < 7.0`: emit an `observation` dict
- Emit one `observation(type="server_banner")` per detected header with full version detail
- Remove the CORS check entirely (was misplaced here)

**Outputs (via base_tool.py `_process_result`):**

| Result type | DB table | When |
|-------------|----------|------|
| `vulnerability` | `Vulnerability` | CVE CVSS ≥ 7.0 |
| `observation(type="server_banner")` | `Observation` | Any detected version header |
| `observation(type="server_cve_low")` | `Observation` | CVE CVSS < 7.0 |

**Weight:** `LIGHT` (HTTP + external API calls only, no subprocess)

**Note:** This tool embeds an inline Python script (consistent with existing pattern) that uses `httpx` for both the target probe and NVD API call.

---

### 2. `AdminInterfaceFinder` (new)

**File:** `workers/config_mgmt/tools/admin_interface_finder.py`

**Responsibility:** Enumerate all admin/management interfaces — both HTTP-accessible paths and non-HTTP services — and map open infrastructure.

**Implementation:**

**Phase A — Port scan:**
```
nmap -p- -sV --open -oG - <target_host>
```
Parse greppable output to extract open ports and service banners. Flag known admin-service ports:

| Port(s) | Service |
|---------|---------|
| 21 | FTP |
| 2049 | NFS |
| 445 | SMB/CIFS |
| 161/udp | SNMP |
| 623 | IPMI/BMC |
| 8080, 8443, 8888 | Alternative HTTP (Tomcat, Jetty, etc.) |
| 9200, 9300 | Elasticsearch |
| 6379 | Redis |
| 27017 | MongoDB |
| 5432, 3306, 1433 | Database management ports |

**Phase B — HTTP admin path probing:**
Expanded path list (beyond current 17) covering:
- Generic: `/admin`, `/administrator`, `/admin/login`, `/manage`, `/manager`, `/console`
- Server-specific: `/server-status`, `/nginx_status`, `/server-info`
- App servers: `/actuator`, `/actuator/health`, `/actuator/env`, `/manager/html`, `/host-manager/html`
- CMS: `/wp-admin`, `/wp-login.php`, `/administrator/index.php` (Joomla), `/admin.php` (various)
- Infrastructure: `/phpmyadmin`, `/pma`, `/cpanel`, `/webmin`, `/kibana`, `/solr`, `/jenkins`, `/grafana`
- Cloud/DevOps: `/.env`, `/config.php`, `/web.config`, `/.git/HEAD`

For each path: record 200 responses as `admin_interface` observations, 301/302/307 as `admin_redirect` observations.

**Outputs:**

| Result type | DB table | When |
|-------------|----------|------|
| `observation(type="admin_interface")` | `Observation` | HTTP 200 on admin path; details include URL, response size, server header |
| `observation(type="admin_redirect")` | `Observation` | HTTP redirect from admin path |
| `observation(type="open_service")` | `Observation` | Open port from nmap; details include port, protocol, service, version banner |

**Weight:** `HEAVY` (nmap full-range port scan is resource-intensive)

---

### 3. `DefaultCredentialTester` (new)

**File:** `workers/config_mgmt/tools/default_credential_tester.py`

**Responsibility:** Attempt default credential login on each HTTP admin interface discovered in the previous stage.

**Discovery:** Queries the DB for `Observation` rows where:
- `observation_type = "admin_interface"`
- `source_tool = "admin_interface_finder"`
- `target_id = <current_target_id>`

**Per-product wordlists:**

| Detected path | Hydra module | Username list | Password list |
|---------------|-------------|--------------|--------------|
| `/wp-admin`, `/wp-login.php` | `http-form-post` | `admin`, `administrator` | `admin`, `password`, `wordpress` |
| `/manager/html` (Tomcat) | `http-form-post` | `tomcat`, `admin`, `manager` | `tomcat`, `s3cret`, `manager` |
| `/solr` | `http-get` | `solr` | `SolrRocks`, `admin` |
| `/jenkins` | `http-form-post` | `admin`, `jenkins` | `admin`, `jenkins`, `password` |
| `/kibana` | `http-form-post` | `elastic`, `kibana` | `changeme`, `elastic` |
| Generic fallback | `http-form-post` | `admin`, `root`, `administrator` | `admin`, `password`, `123456`, `root` |

**Hydra invocation:**
```
hydra
  -L <userlist_path>
  -P <passlist_path>
  -t 1                            # single thread
  -w <jitter>                     # random 3-8s wait between attempts
  -o /tmp/hydra_result_<id>.txt
  -s <port>
  -m "/<path>:user=^USER^&pass=^PASS^:F=<failure_string>:H=User-Agent: <random_ua>"
  http-form-post
  <host>
```

**Rate-limiting:**
- `CONF_CRED_RATE_LIMIT` env var (default `3`): minimum seconds between attempts per host
- Random jitter: `random.uniform(CONF_CRED_RATE_LIMIT, CONF_CRED_RATE_LIMIT * 2.5)`
- Passed to Hydra via `-w` flag

**User-Agent rotation:**
- Small pool of realistic UA strings (Chrome, Firefox, Safari variants)
- Rotated per target via Hydra's `H=User-Agent:` header injection in http-form-post module

**Failure string detection:**
- Default: look for `invalid`, `incorrect`, `failed`, `error` in response
- Per-product overrides where known (e.g. WordPress: `F=is wrong`)

**Outputs:**

| Result type | DB table | When |
|-------------|----------|------|
| `vulnerability(severity="critical")` | `Vulnerability` | Hydra finds valid credentials |
| `observation(type="credential_test_result")` | `Observation` | Per-host test completion; details include tested URL, attempt count, outcome |

**Weight:** `HEAVY` (Hydra subprocess, rate-limited but still blocking)

---

## Concurrency.py Changes

Replace the stale/mismatched `TOOL_WEIGHTS` entries with actual class names:

```python
# New / corrected entries
"NetworkConfigTester": WeightClass.LIGHT,
"AdminInterfaceFinder": WeightClass.HEAVY,
"DefaultCredentialTester": WeightClass.HEAVY,
```

Remove the orphaned entries (`NetworkConfigAuditor`, `AdminFinder`, `DefaultCredChecker`, etc.) that reference class names that do not exist in any tool file.

---

## Three-Layer Sync

All three files must be updated in the same commit (CLAUDE.md coherence rule):

### `workers/config_mgmt/pipeline.py`

```python
STAGES = [
    Stage("network_config",           [NetworkConfigTester, AdminInterfaceFinder]),
    Stage("network_config_cred_test", [DefaultCredentialTester]),
    Stage("platform_config",          [PlatformFingerprinter]),
    # ... remaining stages unchanged
]
```

### `shared/lib_webbh/playbooks.py`

```python
"config_mgmt": [
    "network_config",
    "network_config_cred_test",  # new
    "platform_config",
    "file_extension_handling",
    "backup_files",
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
  { id: "1",  name: "Network Configuration", stageName: "network_config",           sectionId: "WSTG-CONF-01" },
  { id: "1b", name: "Credential Testing",    stageName: "network_config_cred_test", sectionId: "WSTG-CONF-01" },
  { id: "2",  name: "Platform Configuration", stageName: "platform_config",         sectionId: "WSTG-CONF-02" },
  // ... remaining entries unchanged, renumber if needed
]
```

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CONF_CRED_RATE_LIMIT` | `3` | Floor (seconds) between Hydra credential attempts per host |
| `TOOL_TIMEOUT` | `600` | Bounds entire tool run (inherited) |
| `HEAVY_CONCURRENCY` | `2` | Max concurrent heavy tools (inherited) |

---

## Files Changed

| File | Action |
|------|--------|
| `workers/config_mgmt/tools/network_config_tester.py` | Refactor: remove CORS, add version extraction + NVD lookup |
| `workers/config_mgmt/tools/admin_interface_finder.py` | New: nmap scan + HTTP admin path probing |
| `workers/config_mgmt/tools/default_credential_tester.py` | New: Hydra wrapper with rate-limiting and UA rotation |
| `workers/config_mgmt/tools/__init__.py` | Add imports for two new tool classes |
| `workers/config_mgmt/concurrency.py` | Fix TOOL_WEIGHTS — replace orphaned names with actual class names |
| `workers/config_mgmt/pipeline.py` | Add `network_config_cred_test` stage; update `network_config` tool list |
| `shared/lib_webbh/playbooks.py` | Add `network_config_cred_test` to config_mgmt stage list |
| `dashboard/src/lib/worker-stages.ts` | Add credential testing entry for config_mgmt |

---

## Out of Scope

- CORS testing (will be addressed when CONF-10 is implemented)
- Non-default credential brute-force (wordlist expansion is a separate pass)
- CVE exploitation (CONF-01 is assessment only; exploitation belongs in a dedicated worker)
- Changes to any worker other than `config_mgmt`
