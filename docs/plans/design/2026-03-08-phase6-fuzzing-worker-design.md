# Phase 6: Fuzzing Worker — Design Document

**Date:** 2026-03-08
**Status:** Approved

## 1. Architecture Overview

**Purpose:** Discover hidden files, directories, virtual hosts, HTTP parameters, and protocol-level weaknesses on target web applications. Runs as a Dockerized worker triggered by the orchestrator when HTTP ports (80/443) are found open.

**Pipeline: 4 stages**

| Stage | Name | Tools | Purpose |
|-------|------|-------|---------|
| 1 | `dir_fuzzing` | FfufTool → FeroxbusterTool → ExtensionFuzzTool | Breadth-first path discovery, recursive depth, then backup/leftover file permutations on dynamic files |
| 2 | `vhost_fuzzing` | VhostFuzzTool | ffuf with `Host: FUZZ.target.com` against known IPs to find hidden virtual hosts |
| 3 | `param_discovery` | ArjunTool | Probe all live URL assets for hidden GET/POST parameters |
| 4 | `header_fuzzing` | HeaderFuzzTool | HTTP header injection (routing bypass) + Content-Type/Accept fuzzing via aiohttp |

**Post-pipeline:** Generate subdomain permutations from discovered patterns and push to `recon_queue` for DNS resolution.

**Queue:** `fuzzing_queue` / `fuzzing_group`
**Container naming:** `webbh-fuzzing-t{target_id}`
**Wordlist strategy:** Baked into Docker image. `rate_limit >= 50` → large list (~220k). `< 50` → small list (~4.7k).

---

## 2. Stage 1 — Directory Fuzzing

Three sequential tools within the stage.

### FfufTool (breadth)

- Queries assets with open HTTP ports (80/443) to build target URL list.
- Runs ffuf flat (no recursion) per base URL: `ffuf -u https://target.com/FUZZ -w <wordlist> -o /tmp/ffuf-out.json -of json`.
- Applies `rate_limit` via `-rate` flag.
- Injects `custom_headers` via `-H` flags.
- Filters with `-mc 200,204,301,302,307,401,403` to capture interesting responses.
- Stores discovered directories in-memory for feroxbuster handoff.

### FeroxbusterTool (depth)

- Takes ffuf's discovered directories as input.
- Runs recursively: `feroxbuster -u https://target.com/discovered-dir/ -w <wordlist> --rate-limit <rate> --json`.
- Injects custom headers via `--headers`.
- Same status code filtering.

### ExtensionFuzzTool (backup permutations)

- Filters all Stage 1 discoveries to files with dynamic extensions (`.php`, `.asp`, `.aspx`, `.jsp`, `.py`, `.rb`, `.js`, `.json`, `.xml`, `.conf`, `.yml`).
- For each, runs ffuf with extension list: `.bak`, `.old`, `.swp`, `.orig`, `~`, `.temp`, `.save`, `.dist`.
- Also checks dotfile prefix pattern (e.g., `.index.php.swp`).
- Uses the small wordlist approach regardless of `rate_limit` since the input set is already filtered.

### Inline response analysis (all three tools)

- Every discovered path is scope-checked via `ScopeManager` before DB insert.
- Paths matching sensitive file patterns → immediate `Alert` + SSE push.
- 401/403 responses → saved as low-severity `Vulnerability` for webapp worker bypass attempts.

---

## 3. Stage 2 — VHost Fuzzing

### VhostFuzzTool

**Target selection:**
- Queries assets with `asset_type="domain"` or `"ip"` that have open HTTP ports.
- Resolves each domain to its IP address for the actual request target.

**Wordlist construction:**
- Extracts prefixes from already-discovered subdomains (e.g., `dev.target.com` → `dev`).
- Merges with SecLists `Discovery/DNS/subdomains-top1million-5000.txt` for common prefixes.
- Deduplicates the combined list.

**Execution (per ffuf docs):**
- Runs: `ffuf -u https://<IP> -H "Host: FUZZ.target.com" -w <combined-wordlist>`.
- Establishes a baseline by measuring the default response size (what the server returns for a non-existent vhost).
- Filters noise with `-fs <baseline-size>` to auto-calibrate and only surface vhosts that return a different response.
- Applies `rate_limit` via `-rate` and injects `custom_headers` via additional `-H` flags.

**Result handling:**
- Each valid vhost is scope-checked via `ScopeManager`.
- In-scope vhosts are inserted into `assets` table with `asset_type="domain"`, `source_tool="ffuf-vhost"`.
- Corresponding `Location` rows created for the port/protocol.
- Sensitive-looking vhosts (containing `admin`, `internal`, `staging`, `debug`) trigger an `Alert` + SSE push.

---

## 4. Stage 3 — Parameter Discovery

### ArjunTool

**Target selection:**
- Queries all assets with `asset_type="url"` for the target.
- Includes both pre-existing endpoints and newly discovered paths from Stages 1–2.
- Deduplicates URLs to avoid scanning the same endpoint twice.

**Execution:**
- Runs: `arjun -u <url> -oJ /tmp/arjun-out.json --stable`.
- `--stable` flag for reliability (uses consistent response comparison).
- Applies rate limiting via `--delay` (converted from `rate_limit` req/s to millisecond delay between requests).
- Injects `custom_headers` via `--headers`.
- Discovers both GET and POST parameters by default.

**Result handling:**
- Each discovered parameter is inserted into the `parameters` table with:
  - `asset_id` — linked to the URL's asset row.
  - `param_name` — the discovered parameter name.
  - `param_value` — empty string (discovery only, no value exploitation).
  - `source_url` — the full URL where the parameter was found.
- Uses the existing `UniqueConstraint("asset_id", "param_name")` to skip duplicates.
- High-value parameter names (`debug`, `admin`, `test`, `load_config`, `proxy`, `callback`, `token`, `secret`) trigger an `Alert` with `alert_type="high"` + SSE push.

---

## 5. Stage 4 — Header Fuzzing

### HeaderFuzzTool (custom aiohttp client)

Two sub-tasks run sequentially against all live URL assets.

### Sub-task A: HTTP Header Injection (routing bypass)

Sends requests with injected headers to detect routing misconfigurations:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Forwarded-For` | `127.0.0.1` | Bypass IP-based restrictions |
| `X-Original-URL` | `/admin` | Bypass WAF path filters |
| `X-Rewrite-URL` | `/admin` | Same as above, alternate header |
| `True-Client-IP` | `127.0.0.1` | Bypass geo-fencing |
| `X-Real-IP` | `127.0.0.1` | Bypass IP allowlists |
| `X-Forwarded-Host` | `localhost` | Host header manipulation |

- For each endpoint, sends a baseline request (no extra headers), then one request per injected header.
- Compares response status code, body length, and key content against baseline.
- A significant deviation (different status code, or body length diff > 10%) indicates a potential bypass.
- Findings saved as `Vulnerability` with severity based on impact (status code change to 200 on a previously 403 path → `high`; body length change only → `low`).

### Sub-task B: Content-Type/Accept Fuzzing

Targets endpoints that returned JSON or form-encoded responses:

| Content-Type tested | Purpose |
|---------------------|---------|
| `application/xml` | Trigger XXE processing |
| `text/yaml` | Trigger YAML deserialization |
| `text/xml` | Alternate XML parser |
| `application/x-www-form-urlencoded` | Format confusion |

- Sends POST requests with a benign XML payload containing a harmless entity declaration to detect XXE reflection.
- Inspects responses for: XML parsing errors, verbose stack traces, format-specific error messages, entity reflection.
- Findings saved as `Vulnerability` (XXE indicator → `critical`; verbose errors → `medium`).

**Shared controls:** Respects `rate_limit` via `asyncio.Semaphore` + delay. Custom headers from target profile always included alongside test headers.

---

## 6. Post-Pipeline — Subdomain Permutation Handoff

Runs after Stage 4 completes, before marking pipeline as done.

**Permutation generation:**
- Queries all `asset_type="domain"` assets for the target.
- Extracts subdomain prefixes (e.g., `dev.target.com` → `dev`, `api.staging.target.com` → `api.staging`).
- Applies a set of common mutations to each prefix:
  - Suffixes: `-api`, `-admin`, `-staging`, `-test`, `-v2`, `-internal`, `-dev`, `-prod`, `-qa`, `-uat`.
  - Prefixes: `v1.`, `v2.`, `new.`, `old.`, `beta.`, `alpha.`.
  - Separators: swaps `-` for `.` and vice versa (e.g., `dev-api` → `dev.api`).
- Deduplicates against existing assets to avoid re-resolving known subdomains.

**Handoff:**
- Pushes batches to `recon_queue` with metadata:
  ```python
  await push_task("recon_queue", {
      "target_id": target_id,
      "source": "fuzzing_permutation",
      "domains": ["dev-api.target.com", "dev-staging.target.com", ...],
  })
  ```
- The `source: "fuzzing_permutation"` flag tells the recon worker to only perform DNS resolution (not a full pipeline run).
- Batched in groups of 100 domains per message to avoid oversized payloads.
- Logs the count of generated permutations and how many were novel (not already in assets).

---

## 7. Sensitive File Detection & Alert Patterns

Static regex pattern list applied inline during Stages 1–2.

### Pattern categories

```
Category: Configuration Files
  \.env$, \.env\..+, web\.config, \.htaccess, \.htpasswd,
  wp-config\.php, config\.php, settings\.py, application\.yml,
  \.npmrc, \.pypirc, composer\.json, package\.json

Category: Backup / Leftover Files
  \.(bak|old|orig|save|swp|temp|dist|copy)$, ~$,
  ^\..+\.swp$  (vim swap files)

Category: Source Control
  \.git/config, \.git/HEAD, \.svn/entries, \.hg/

Category: Credentials / Keys
  id_rsa, id_dsa, id_ecdsa, \.pem$, \.key$, \.pfx$,
  credentials\.json, \.aws/credentials, \.ssh/

Category: Database
  \.(sql|sqlite|sqlite3|db|dump)$

Category: Logs / Debug
  \.(log|debug)$, phpinfo\.php, server-status, server-info,
  elmah\.axd, trace\.axd
```

### Alert behavior

- Match detected → create `Vulnerability` row (severity `critical` for keys/credentials, `high` for config/source control, `medium` for backups/logs).
- Create `Alert` row linked to the vulnerability.
- Push SSE event: `push_task(f"events:{target_id}", {"event": "critical_alert", ...})`.
- Logger emits a warning-level message with the matched path and pattern category.

### 403/401 flagging (separate from alerts)

- Saved as `Vulnerability` with severity `info`, title `"Access Restricted — potential bypass target"`.
- No alert created — these are informational for the webapp worker.

---

## 8. Resource Control & Concurrency

### Rate limiting

- `rate_limit` sourced from `target.target_profile` (default: 50 req/s).
- Applied per-tool:
  - ffuf: `-rate <rate_limit>`
  - feroxbuster: `--rate-limit <rate_limit>`
  - Arjun: `--delay <1000/rate_limit>` (converted to ms between requests)
  - aiohttp (header fuzzing): `asyncio.Semaphore(rate_limit)` with 1-second sliding window

### Concurrency model (mirrors existing workers)

- `WeightClass.HEAVY` — ffuf, feroxbuster, Arjun (subprocess-based, high I/O). Capped at `HEAVY_CONCURRENCY` env var (default 2).
- `WeightClass.LIGHT` — extension fuzz pass, header fuzzing, permutation generation. Capped at `LIGHT_CONCURRENCY` env var (default `os.cpu_count()`).
- Within a stage, tools run sequentially when they depend on prior output (ffuf → feroxbuster → extension fuzz). Independent tools could run in parallel via `asyncio.gather`.

### Subprocess management

- All CLI tools run with `TOOL_TIMEOUT` env var (default 600s / 10 min per invocation).
- Output written to JSON temp files, parsed after completion.
- Failed subprocesses logged and skipped — don't block the pipeline.

### Cooldown

- 24-hour cooldown per tool per target (via `check_cooldown` checking `JobState.last_tool_executed` timestamps).
- Prevents redundant scanning on re-triggers.

### Heartbeat

- Async task updates `JobState.last_seen` every `HEARTBEAT_INTERVAL` seconds (default 30).
- Orchestrator uses this to detect stalled workers.

---

## 9. Directory Structure & File Inventory

```
workers/fuzzing_worker/
├── __init__.py
├── main.py                    # Queue listener, message handler, heartbeat
├── pipeline.py                # 4-stage pipeline with resume support
├── base_tool.py               # FuzzingTool ABC (execute, DB helpers, subprocess)
├── concurrency.py             # WeightClass enum + semaphore management
├── sensitive_patterns.py      # Regex pattern list + match function
├── permutation.py             # Subdomain permutation generator + recon handoff
└── tools/
    ├── __init__.py
    ├── ffuf_tool.py           # Stage 1: flat directory fuzzing
    ├── feroxbuster_tool.py    # Stage 1: recursive content discovery
    ├── extension_fuzz_tool.py # Stage 1: backup/leftover file permutations
    ├── vhost_fuzz_tool.py     # Stage 2: virtual host discovery via ffuf
    ├── arjun_tool.py          # Stage 3: HTTP parameter discovery
    └── header_fuzz_tool.py    # Stage 4: header injection + content-type fuzzing

docker/Dockerfile.fuzzing      # Multi-stage: Go (ffuf, feroxbuster) + Py (arjun) + SecLists

tests/
├── test_fuzzing_pipeline.py   # Pipeline stage ordering, resume, completion
├── test_fuzzing_tools.py      # Unit tests per tool (mocked subprocess/HTTP)
└── test_fuzzing_integration.py # End-to-end with in-memory DB
```

### Docker image contents

- Go binaries: `ffuf`, `feroxbuster`
- Python packages: `arjun`, `aiohttp`
- SecLists (compressed): `Discovery/Web-Content/common.txt`, `directory-list-2.3-medium.txt`, `Discovery/DNS/subdomains-top1million-5000.txt`
- Shared lib: `lib_webbh`

---

## 10. Database Interactions Summary

| Action | Table | When | Key Fields |
|--------|-------|------|------------|
| Insert discovered path | `assets` | Stages 1, 2 | `asset_type="url"`, `source_tool="ffuf"/"feroxbuster"/"ffuf-ext"/"ffuf-vhost"` |
| Insert vhost domain | `assets` | Stage 2 | `asset_type="domain"`, `source_tool="ffuf-vhost"` |
| Insert port/protocol | `locations` | Stage 2 (vhosts) | `port`, `protocol`, `service="http"`, `state="open"` |
| Insert parameter | `parameters` | Stage 3 | `param_name`, `param_value=""`, `source_url` |
| Insert sensitive file finding | `vulnerabilities` | Stages 1, 2 | `severity="critical"/"high"/"medium"`, `source_tool` |
| Insert bypass/protocol finding | `vulnerabilities` | Stage 4 | `severity` based on impact, `poc` with request/response diff |
| Insert 403/401 flag | `vulnerabilities` | Stages 1, 2 | `severity="info"`, `title="Access Restricted — potential bypass target"` |
| Create alert | `alerts` | On sensitive file or critical finding | `alert_type`, `message`, linked `vulnerability_id` |
| Update job state | `job_state` | Every stage transition + heartbeat | `current_phase`, `status`, `last_seen`, `last_tool_executed` |
| Push to recon | `recon_queue` (Redis) | Post-pipeline | `source="fuzzing_permutation"`, `domains=[...]` |
| Push SSE events | `events:{target_id}` (Redis) | Stage complete, alerts | `event` type + payload |

**Deduplication:** All asset inserts check for existing `(target_id, asset_type, asset_value)` before inserting. Parameter inserts rely on the `UniqueConstraint("asset_id", "param_name")`.
