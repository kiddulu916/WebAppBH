# Phase 11 — Network Testing Worker Design

**Date:** 2026-03-19
**Phase prompt:** `docs/plans/phase_prompts/phase11.md`

---

## 1. Architecture Overview

The **Network Testing Worker** (`network_worker`) is a Dockerized service that performs deep port enumeration, service fingerprinting, credential testing, LDAP injection, and safe exploit verification against non-HTTP network services.

**Container:** Kali Linux slim base with Nmap, Metasploit (msfrpcd), Naabu, Medusa, and Socat installed via `apt`/binary download. The msfrpcd daemon starts on container boot and listens on localhost for `pymetasploit3` connections from the Python controller.

**Queue:** Listens on `network_queue` via Redis Streams consumer group. Messages contain `target_id` and `container_name`.

**Config:** Reads target scope and `oos_attacks` exclusion list from `shared/config/{target_id}/profile.json`, consistent with all other workers.

**Data flow:**

1. Orchestrator pushes task to `network_queue`
2. Worker reads scope + exclusion config from filesystem
3. 4-stage pipeline runs sequentially with checkpointing via `job_state`
4. Results written to `locations`, `observations` (tech_stack), and `vulnerabilities` tables
5. SSE events pushed to `events:{target_id}` for dashboard consumption

**Package structure** follows the standard worker pattern: `base_tool.py`, `pipeline.py`, `concurrency.py`, `main.py`, `tools/`, plus `wordlists/` for credential configs and `mappings/` for CVE-to-MSF mappings.

---

## 2. Pipeline Stages & Tools

### Stage 1 — `port_discovery`

- **NaabuTool**: Fast SYN scan across all ports on target assets (IPs/domains from `assets` table). Outputs open port list. Results upserted into `locations` table with `state="open"`.

### Stage 2 — `service_scan`

- **NmapTool**: Runs `nmap -sV -sC --script=vuln` against ports discovered in Stage 1. Parses XML output for service versions, CVE references, and OS fingerprint. Updates `locations` with `service` and `protocol` fields. Stores OS fingerprint and version details in `observations.tech_stack` JSON. Filters out any NSE scripts listed in `oos_attacks`.
- **BannerGrabTool**: Uses Socat to probe unidentified services with raw banner grabs. Detects LDAP services (ports 389/636) that Nmap may have fingerprinted generically. Updates `locations.service` accordingly.

### Stage 3 — `credential_test`

- **MedusaTool**: Runs Medusa against services with known default credential pairs (SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, Telnet). Loads credential lists from `wordlists/default_creds.yaml`. Rate-limited to 1-2 attempts/sec. Successful logins → `vulnerabilities` table as "high" severity.
- **LdapInjectionTool**: Targets services identified as LDAP in Stage 2. Runs filter manipulation (`*)(uid=*`), blind injection via timing, auth bypass (`*)(&`), and wildcard extraction. Findings → `vulnerabilities` with full payload + response as PoC.

### Stage 4 — `exploit_verify`

- **MsfCheckTool**: Looks up confirmed CVEs from Stage 2 against `mappings/cve_to_msf.yaml`. Connects to local msfrpcd via `pymetasploit3`, runs `check` command only (no payload execution). Results → `vulnerabilities` with severity based on exploitability confirmation.

---

## 3. Base Tool & Concurrency

### `NetworkTestTool` (base_tool.py)

Abstract base class following the established pattern from `CloudTestTool`:

- `name` and `weight_class` class attributes
- `execute()` abstract method with signature: `(target, scope_manager, target_id, container_name, **kwargs) -> dict`
- `run_subprocess()` — async subprocess runner with configurable timeout (default `TOOL_TIMEOUT=600s`)
- `check_cooldown()` / `update_tool_state()` — same JobState-based cooldown pattern
- **DB helpers**: `_save_location()` (upsert into `locations`), `_save_observation()` (upsert `tech_stack` JSON), `_save_vulnerability()` + auto-alert for critical/high
- **Config helpers**: `_load_oos_attacks(target_id)` reads exclusion list from profile JSON, `_get_non_http_locations(target_id)` queries locations for non-HTTP ports to scan
- **MSF helper**: `_get_msf_client()` returns a `pymetasploit3.MsfRpcClient` connected to the local msfrpcd instance

### Concurrency (`concurrency.py`)

Semaphore-based with weight classes:

| Weight | Semaphore slots | Tools |
|--------|----------------|-------|
| LIGHT | 4 | NaabuTool, BannerGrabTool |
| MEDIUM | 2 | NmapTool, MedusaTool, LdapInjectionTool |
| HEAVY | 1 | MsfCheckTool |

MSF gets exclusive access (weight=HEAVY) since msfrpcd handles one check at a time. Naabu and banner grabs are lightweight and can run in parallel.

---

## 4. Dockerfile & Container Startup

### `docker/Dockerfile.network`

Single-stage Kali slim build:

```
kali-rolling (slim) base
  → apt install: nmap, metasploit-framework, medusa, socat, python3, pip
  → binary install: naabu (Go binary from GitHub release)
  → pip install: pymetasploit3, lib_webbh (editable)
  → copy: workers/network_worker/, wordlists/, mappings/
```

### Container entrypoint sequence (main.py)

1. Start `msfrpcd` as a background subprocess (localhost:55553, password from env var `MSFRPC_PASS`, default `msf_internal`)
2. Wait for msfrpcd to be ready (poll connection with retry)
3. Initialize MSF database (`msfdb init`) for module search support
4. Call `listen_queue("network_queue", ...)` to begin processing tasks

### docker-compose entry

```yaml
network-worker:
  build:
    context: .
    dockerfile: docker/Dockerfile.network
  depends_on: [postgres, redis]
  env_file: shared/config/.env
  environment:
    - MSFRPC_PASS=msf_internal
  networks: [bounty_net]
```

Image size estimate: ~2-2.5GB due to MSF + Ruby dependencies.

---

## 5. Data Mappings & Wordlists

### `wordlists/default_creds.yaml`

Service-keyed credential pairs. Small, curated lists — default credential checking, not brute-forcing. Each service gets 2-5 pairs max.

```yaml
ssh:
  - ["root", "root"]
  - ["admin", "admin"]
  - ["admin", "password"]
mysql:
  - ["root", ""]
  - ["root", "root"]
postgresql:
  - ["postgres", "postgres"]
redis:
  - ["", ""]           # no-auth check
mongodb:
  - ["admin", "admin"]
ftp:
  - ["anonymous", ""]
  - ["admin", "admin"]
telnet:
  - ["admin", "admin"]
  - ["root", "root"]
```

### `mappings/cve_to_msf.yaml`

Static CVE-to-module mapping. Only modules verified to support `check` without side effects are included.

```yaml
CVE-2017-0144:
  module: exploit/windows/smb/ms17_010_eternalblue
  service: smb
  ports: [445]
CVE-2019-0708:
  module: exploit/windows/rdp/cve_2019_0708_bluekeep_rce
  service: rdp
  ports: [3389]
# ... curated list of ~20-30 high-impact CVEs with safe check support
```

Each entry includes `module`, `service`, and `ports` so the MsfCheckTool can match CVEs found by Nmap's NSE output against the right module.

---

## 6. Safety & Ethical Controls

### Exclusion enforcement (`oos_attacks`)

- Loaded once at pipeline start from `shared/config/{target_id}/profile.json`
- Passed to every tool via `**kwargs`
- **NmapTool**: Filters `--script` arguments — any NSE script name in `oos_attacks` is excluded from the command. If `dos` or `exploit` categories are excluded, those entire NSE categories are blocked
- **MsfCheckTool**: If a module path appears in `oos_attacks`, it is skipped entirely regardless of CVE match

### Rate limiting

- MedusaTool enforces `-t 1` (single thread) and `-w 2` (2-second wait between attempts) — hardcoded, not configurable, to prevent accidental lockouts
- LdapInjectionTool adds a 1-second `asyncio.sleep` between injection payloads

### Scope checking

- Every target IP/domain is validated against `ScopeManager` before any tool runs
- NaabuTool and NmapTool reject out-of-scope targets at the tool level, not just the pipeline level

### No destructive payloads

- MsfCheckTool uses `check` only — never `exploit` or `run`
- No DoS-category NSE scripts are included by default
- LdapInjectionTool uses read-only filter manipulation — no write operations (modify/delete) against LDAP directories

### Logging

- All tool executions logged with `target_id`, tool name, and outcome via `setup_logger`
- Failed scope checks logged as warnings for audit trail

---

## 7. Error Handling & Reporting

### Tool-level errors

- Each tool's `execute()` wraps its work in try/except. Failures return `{"found": 0, "in_scope": 0, "new": 0, "error": str(e)}`
- `pipeline._aggregate_results()` logs tool exceptions but does not halt the stage — other tools in the same stage continue
- msfrpcd connection failures in MsfCheckTool are logged and the tool returns gracefully (no vulns verified rather than pipeline crash)

### Checkpointing

- Standard `JobState` checkpointing per stage. If the container restarts mid-pipeline, it resumes from the last completed stage
- `update_tool_state()` called after each individual tool completes within a stage

### Reporting to DB

- `locations` — Updated in Stages 1 and 2 (ports, services, protocols)
- `observations.tech_stack` — OS fingerprint, service versions, uptime stored as JSON keys in Stage 2
- `vulnerabilities` — Written in Stages 3 and 4 with severity levels:
  - **critical**: RCE-capable exploit verified by MSF `check`
  - **high**: Successful default credential login, LDAP auth bypass
  - **medium**: LDAP data extraction, vulnerable service version (unverified)
  - **info**: Service banner details, OS fingerprint

### Alerting

- Critical and high severity vulnerabilities trigger `_create_alert()` → Alert row + SSE push to `events:{target_id}`
- Matches the existing alert pattern from CloudTestTool

---

## Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| MSF integration | msfrpcd + pymetasploit3 | Avoids cold-start, structured results |
| LDAP target discovery | DB-driven + light banner probing | Catches generically fingerprinted LDAP |
| Credential lists | YAML config files in `wordlists/` | Version-controlled, easy to extend |
| Exclusion config | Target profile JSON | Consistent with other workers |
| OS fingerprint storage | `observations.tech_stack` JSON | No schema migration needed |
| Pipeline stages | 4 stages (discovery → scan → creds → exploit) | Clean data dependencies |
| CVE-to-MSF mapping | Static YAML | Predictable, auditable, safe |
| Base image | Kali Linux slim | MSF package management, simpler Dockerfile |
