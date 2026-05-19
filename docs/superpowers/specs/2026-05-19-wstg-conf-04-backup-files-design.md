# WSTG-CONF-04: Backup and Unreferenced Files — Design Spec

**Date:** 2026-05-19
**Stage:** `backup_files` (pipeline index 4)
**Worker:** `config_mgmt`
**OWASP ref:** WSTG-CONF-04 — Review Old Backup and Unreferenced Files for Sensitive Information
**Tool files:** `workers/config_mgmt/tools/backup_file_finder.py`, `workers/config_mgmt/tools/ffuf_tool.py`

---

## Objective

Rewrite `BackupFileFinder` and extend `FfufTool` to fully implement WSTG-CONF-04. The current `BackupFileFinder` is a subprocess inline Python script probing ~60 hardcoded paths with no dynamic path mutation, no source code disclosure detection, and no robots.txt mining. `FfufTool` only fuzzes the webroot and has no DB awareness or backup-aware severity classification.

The rewrite must:

- Rewrite `BackupFileFinder` as a pure async httpx tool (following the `FileExtensionTester` pattern) with five probe phases driven by DB-discovered paths
- Extend `FfufTool` to fuzz all discovered directories (not just webroot), inject a supplemental backup-extension wordlist, and classify findings by file type
- Assign `section_id = "WSTG-CONF-04"` on every vulnerability row from both tools

No changes are required to `pipeline.py`, `playbooks.py`, `dashboard/worker-stages.ts`, `concurrency.py`, or `tools/__init__.py`.

---

## Architecture

Two tools in the `backup_files` stage serve complementary WSTG-CONF-04 roles:

```
backup_files stage
├── BackupFileFinder   ← targeted probing (named paths, dynamic mutation)
│   Guide sections: Naming scheme inference, Published content analysis,
│                   Server misconfiguration, File system snapshots
│
└── FfufTool           ← broad wordlist discovery (blind guessing)
    Guide section:  Blind guessing
```

Both run concurrently via `asyncio.gather` in `pipeline._run_stage()`.

---

## BackupFileFinder Rewrite

### Lifecycle

`BackupFileFinder` overrides `execute()` entirely. `build_command()` and `parse_output()` are ABC stubs that raise `NotImplementedError` — they satisfy the contract but are never called.

```
execute(target, scope_manager, target_id, container_name, headers)
 ├─ check_cooldown()                    → early return if within cooldown
 ├─ acquire_semaphore (global)
 ├─ emit TOOL_PROGRESS: started
 │
 ├─ [Phase 0 — DB + robots.txt reads]
 │   ├─ SELECT asset_value WHERE asset_type IN ('url','page','endpoint')
 │   │   → extract (stem, ext) pairs and unique directory paths
 │   ├─ derive bare domain from target.target_value
 │   └─ GET /robots.txt → extract Disallow: paths
 │
 ├─ [Five probe phases — asyncio.gather, inner Semaphore(20)]
 │   ├─ Phase 1: Static probes      (hardcoded sensitive paths)
 │   ├─ Phase 2: Dynamic mutation   (discovered stem+ext → backup variants)
 │   ├─ Phase 3: Directory backups  (discovered dirs → _backup, _bak, .old variants)
 │   ├─ Phase 4: Archive probing    (domain-named and generic archives)
 │   └─ Phase 5: robots.txt paths   (Disallow: entries → HEAD probe)
 │
 ├─ [Persist]
 │   └─ _process_vulnerability() or _process_observation() per finding
 │
 ├─ update job_state.last_tool_executed
 ├─ emit TOOL_PROGRESS: finished
 └─ return {found, in_scope, new, skipped_cooldown}
```

### Phase 1 — Static Probes

Hardcoded paths probed unconditionally. Categories:

| Category | Paths |
|---|---|
| Source control | `/.git/HEAD`, `/.git/config`, `/.git/index`, `/.svn/entries`, `/.hg/`, `/.bzr/` |
| Environment / secrets | `/.env`, `/.env.local`, `/.env.production`, `/.env.development`, `/.env.bak`, `/.env.old` |
| Server config | `/.htaccess`, `/.htpasswd`, `/web.config`, `/web.config.bak` |
| Metadata | `/.DS_Store`, `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`, `/clientaccesspolicy.xml` |
| Editor backups | `/index.php~`, `/index.php.bak`, `/index.php.old`, `/index.php.orig`, `/index.php.swp`, `/config.php.bak`, `/wp-config.php.bak`, `/settings.py.bak` |
| DB dumps | `/dump.sql`, `/dump.sql.gz`, `/backup.sql`, `/database.sql`, `/db.sql`, `/export.sql`, `/mysqldump.sql`, `/pg_dump.sql` |
| Config backups | `/config.bak`, `/config.old`, `/config.yml.bak`, `/config.yaml.bak`, `/config.ini.bak`, `/application.yml.bak`, `/settings.json.bak` |
| Deployment artifacts | `/.dockerignore`, `/Dockerfile`, `/docker-compose.yml`, `/Makefile`, `/package.json`, `/requirements.txt`, `/composer.json`, `/pom.xml`, `/go.mod` |

Source control dirs (`.git/`, `.svn/`, `.hg/`) are flagged on HTTP 200 **or** 403 — both indicate the directory exists.

### Phase 2 — Dynamic Mutation

For each `(stem, ext)` pair extracted from DB-discovered assets (e.g. `/login.php` → stem=`/login`, ext=`.php`), probe:

```
stem + ext + .bak       → /login.php.bak
stem + ext + ~          → /login.php~
stem + ext + .old       → /login.php.old
stem + ext + .orig      → /login.php.orig
stem + ext + .swp       → /login.php.swp
stem + ext + .copy      → /login.php.copy
stem + ext + .tmp       → /login.php.tmp
stem + ext + .src       → /login.php.src
stem + ext + .dev       → /login.php.dev
stem + ext + .inc       → /login.php.inc
stem + ext + .txt       → /login.php.txt
stem + .bak             → /login.bak
stem + .old             → /login.old
```

### Phase 3 — Directory Backup Variants

For each unique directory path extracted from DB assets (e.g. `/app/admin/`), probe:

```
/app/admin_backup/
/app/admin_bak/
/app/admin.old/
/app/admin_old/
/app/admin.backup/
```

A 200 response is a vulnerability (`medium` severity). A 403 response is an observation (`backup_access_denied`) — the directory exists but is blocked.

### Phase 4 — Archive Probing

Generic archives always probed:
```
/backup.zip, /backup.tar.gz, /backup.tgz
/www.zip, /www.tar.gz
/site.zip, /site.tar.gz
/web.zip, /web.tar.gz
/htdocs.zip, /public_html.zip
```

Domain-named archives (derived from `target.target_value` bare hostname, e.g. `example.com`):
```
/example.com.zip
/example.com.tar.gz
/example.zip
/example.tar.gz
```

### Phase 5 — robots.txt Path Probing

Fetch `/robots.txt` once. For each `Disallow:` entry, send HEAD to that path:
- 200 → vulnerability (`low` severity — accessible but disallowed)
- 403 → observation (`backup_access_denied`) — exists but blocked
- Skip 404 entries

### Content Analysis

Applied to every HTTP 200 response body across all phases:

**Source code disclosure** — check for raw template syntax:
```
<?php, <?=, <%, <%@, response.write, <jsp:, {%, {{,
#!/usr/bin/env python, #!/usr/bin/perl, #!/usr/bin/ruby
```
Also check `Content-Type: text/plain` or `application/octet-stream` on a script extension.

**Credential patterns** (case-insensitive):
```
password, passwd, api_key, apikey, secret, token,
db_pass, database_url, mysql://, postgres://,
connection_string, private_key
```

---

## FfufTool Extension

`FfufTool` keeps its subprocess `build_command` / `parse_output` pattern (wrapping an external binary). Three additions:

### 1. Multi-Directory Fuzzing

Before building the command, query the DB:
```sql
SELECT asset_value FROM assets
WHERE target_id = :tid
AND asset_type IN ('url', 'page', 'endpoint', 'directory');
```

Extract unique parent directory paths. Build one ffuf invocation per target URL — webroot plus up to **10 discovered directories** (capped to bound runtime):

```
{base_url}/FUZZ
{base_url}/app/FUZZ
{base_url}/admin/FUZZ
...
```

Each invocation writes its own temp JSON output file. `parse_output` reads all of them and merges results.

### 2. Supplemental Backup Wordlist

Query the DB for distinct extensions seen on discovered assets. Build a small supplemental wordlist (capped at 200 entries) containing `{common_stem}{discovered_ext}{backup_suffix}` combinations:

Common stems: `index`, `config`, `backup`, `admin`, `login`, `app`, `default`, `web`, `database`, `settings`

Backup suffixes: `.bak`, `.old`, `.orig`, `~`, `.swp`, `.copy`, `.tmp`, `.src`, `.dev`, `.inc`

Pass as a second `-w` argument to ffuf alongside the main wordlist.

### 3. Backup-Aware Severity Classification

`parse_output` classifies discovered paths by filename pattern rather than a flat `medium`/`low`:

| Pattern in discovered path | Severity | Type |
|---|---|---|
| Database extension (`.sql`, `.db`, `.sqlite`) | `critical` | vulnerability |
| Backup extension (`.bak`, `.old`, `~`, `.swp`, `.orig`, `.copy`) | `high` | vulnerability |
| Archive extension (`.zip`, `.tar`, `.gz`, `.tgz`) | `high` | vulnerability |
| Source extension (`.php`, `.py`, `.rb`, etc.) + HTTP 200 | `medium` | vulnerability |
| 401/403 response on any path | `low` | observation |
| Everything else | `low` | vulnerability |

---

## Severity Classification (unified)

| Condition | Severity |
|---|---|
| Any accessible file + credential pattern in body | `critical` |
| Database file accessible (`.sql`, `.db`, `.sqlite`) | `critical` |
| Source code returned raw (template syntax or `text/plain` on script ext) | `high` |
| Source control dir exposed — HTTP 200 or 403 | `high` |
| Archive file accessible (`.zip`, `.tar.gz`, `.tgz`) | `high` |
| Backup extension on discovered file (`.bak`, `.old`, `~`, `.swp`, `.orig`) | `high` |
| Sensitive config file (`.env`, `.htaccess`, `web.config`, `.htpasswd`) | `high` |
| Directory backup variant accessible (`/admin_bak/`, `/backup/`) | `medium` |
| Generic config backup (`.yml.bak`, `.ini.bak`) | `medium` |
| robots.txt disallowed path accessible | `low` |
| 401/403 on sensitive/backup path | `low` observation |

---

## Data Flow

### DB Reads

```sql
-- Discovered paths for dynamic mutation and directory extraction
SELECT asset_value FROM assets
WHERE target_id = :tid
AND asset_type IN ('url', 'page', 'endpoint');

-- Discovered directories for FfufTool multi-dir fuzzing and Phase 3
SELECT asset_value FROM assets
WHERE target_id = :tid
AND asset_type IN ('url', 'page', 'endpoint', 'directory');

-- Distinct extensions for supplemental wordlist (FfufTool)
SELECT DISTINCT asset_value FROM assets
WHERE target_id = :tid
AND asset_type IN ('url', 'page', 'endpoint');
```

All queries run before any HTTP work. If DB is empty (early-stage run), static probes and generic archives still execute.

### HTTP Client (BackupFileFinder)

- `httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10, headers=headers or {})`
- `follow_redirects=False` — a redirect on a backup path is itself informational
- `asyncio.Semaphore(20)` caps concurrent requests within the tool
- Per-request `httpx.RequestError` silently swallowed — one unreachable path does not abort the scan

### DB Writes

- Vulnerabilities via `_process_vulnerability()` — dedup by `(target_id, title)` in base class
- `section_id = "WSTG-CONF-04"` on every vulnerability row
- `worker_type = "config_mgmt"` on all rows
- Observations (redirects, access-denied) via `_process_observation()` stored as `Asset` rows

### Stats

Standard `{found, in_scope, new, skipped_cooldown}` — no changes to pipeline aggregation.

---

## Files Changed

| File | Change |
|---|---|
| `workers/config_mgmt/tools/backup_file_finder.py` | Full rewrite — async httpx, 5-phase probing |
| `workers/config_mgmt/tools/ffuf_tool.py` | Extend — multi-dir fuzzing, supplemental wordlist, severity classification |

No other files require changes.
