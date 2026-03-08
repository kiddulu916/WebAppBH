# Phase 6: Fuzzing Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Dockerized fuzzing worker with a 4-stage pipeline: directory fuzzing, vhost fuzzing, parameter discovery, and header fuzzing.

**Architecture:** Mirrors `workers/webapp_worker/` — queue listener (`main.py`), staged pipeline (`pipeline.py`), abstract base tool (`base_tool.py`), and individual tool modules. Uses `lib_webbh` for DB, messaging, scope, and logging.

**Tech Stack:** Python 3.10, asyncio, aiohttp, ffuf (Go), feroxbuster (Rust), Arjun (Python), SecLists wordlists, SQLAlchemy async, Redis Streams.

**Design Doc:** `docs/plans/design/2026-03-08-phase6-fuzzing-worker-design.md`

---

## Task 1: Scaffold directory structure and concurrency module

**Files:**
- Create: `workers/fuzzing_worker/__init__.py`
- Create: `workers/fuzzing_worker/tools/__init__.py`
- Create: `workers/fuzzing_worker/concurrency.py`
- Test: `tests/test_fuzzing_pipeline.py`

**Step 1: Create empty package files**

Create `workers/fuzzing_worker/__init__.py` (empty) and `workers/fuzzing_worker/tools/__init__.py` (empty).

**Step 2: Create concurrency.py**

Copy from `workers/webapp_worker/concurrency.py` — identical logic: `WeightClass` enum, `get_semaphores(force_new)`, `get_semaphore(weight)`. Env vars: `HEAVY_CONCURRENCY` (default 2), `LIGHT_CONCURRENCY` (default cpu_count).

**Step 3: Write test**

File: `tests/test_fuzzing_pipeline.py`

```python
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

def test_concurrency_semaphore_defaults():
    from workers.fuzzing_worker.concurrency import WeightClass, get_semaphores
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 2
    assert light._value >= 1
```

**Step 4: Run test**

Run: `python -m pytest tests/test_fuzzing_pipeline.py::test_concurrency_semaphore_defaults -v`
Expected: PASS

**Step 5: Commit**

Message: `feat(fuzzing): scaffold directory structure and concurrency module`

---

## Task 2: Create FuzzingTool base class

**Files:**
- Create: `workers/fuzzing_worker/base_tool.py`
- Modify: `tests/test_fuzzing_pipeline.py`

**Step 1: Write failing tests**

Add to `tests/test_fuzzing_pipeline.py` — helper `_create_tables()` and `_make_dummy_tool()` (concrete subclass of `FuzzingTool`), then tests:

- `test_fuzzing_base_tool_check_cooldown_no_job` — returns False when no matching JobState
- `test_fuzzing_base_tool_save_asset_out_of_scope` — returns None for out-of-scope URL
- `test_fuzzing_base_tool_save_parameter_dedup` — first insert True, second insert False
- `test_fuzzing_base_tool_save_vulnerability_creates_alert` — severity="critical" creates Alert row and calls push_task

Pattern: Mirror test structure from `tests/test_webapp_pipeline.py` lines 88-174.

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_fuzzing_pipeline.py -k "fuzzing_base_tool" -v`
Expected: FAIL — ModuleNotFoundError

**Step 3: Write base_tool.py**

Mirror `workers/webapp_worker/base_tool.py` with these changes:
- Class name: `FuzzingTool` (not `WebAppTool`)
- No `ToolType` enum (unnecessary for this worker)
- Add `_get_all_url_assets(target_id)` method — queries `Asset` where `asset_type="url"`
- Keep all other methods identical: `check_cooldown`, `update_tool_state`, `run_subprocess`, `_get_live_urls`, `_save_asset`, `_save_parameter`, `_save_vulnerability`, `_create_alert`
- Import from `workers.fuzzing_worker.concurrency` instead of webapp

**Step 4: Run tests**

Run: `python -m pytest tests/test_fuzzing_pipeline.py -k "fuzzing_base_tool" -v`
Expected: All 4 PASS

**Step 5: Commit**

Message: `feat(fuzzing): add FuzzingTool abstract base class with DB helpers`

---

## Task 3: Create sensitive_patterns module

**Files:**
- Create: `workers/fuzzing_worker/sensitive_patterns.py`
- Create: `tests/test_fuzzing_tools.py`

**Step 1: Write failing tests**

File: `tests/test_fuzzing_tools.py`

```python
import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

def test_sensitive_match_env_file():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.env")
    assert result is not None
    assert result["severity"] == "critical"
    assert result["category"] == "credentials_keys"

def test_sensitive_match_git_config():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.git/config")
    assert result is not None
    assert result["severity"] == "high"
    assert result["category"] == "source_control"

def test_sensitive_match_backup_file():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/index.php.bak")
    assert result is not None
    assert result["severity"] == "medium"

def test_sensitive_no_match():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/about")
    assert result is None

def test_sensitive_match_sql_dump():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/backup.sql")
    assert result is not None
    assert result["severity"] == "critical"

def test_sensitive_match_vim_swap():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.index.php.swp")
    assert result is not None
    assert result["severity"] == "medium"
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_fuzzing_tools.py -k "sensitive" -v`

**Step 3: Write sensitive_patterns.py**

Module-level list of `(category, severity, compiled_regex)` tuples. Function `check_sensitive(path) -> SensitiveMatch | None` iterates patterns, returns first match.

Categories and severities per design doc Section 7:
- credentials_keys: critical — `.env`, `.htpasswd`, `wp-config.php`, `id_rsa`, `.pem`, `.key`, `.pfx`, `credentials.json`, `.aws/credentials`, `.ssh/`, `.npmrc`, `.pypirc`
- database: critical — `.sql`, `.sqlite`, `.sqlite3`, `.db`, `.dump`
- source_control: high — `.git/config`, `.git/HEAD`, `.svn/entries`, `.hg/`
- configuration: high — `web.config`, `.htaccess`, `application.yml`, `composer.json`, `package.json`
- backup: medium — `.bak`, `.old`, `.orig`, `.save`, `.swp`, `.temp`, `.dist`, `.copy`, `~`, vim swap `^\..+\.swp$`
- logs_debug: medium — `.log`, `.debug`, `phpinfo.php`, `server-status`, `server-info`, `elmah.axd`, `trace.axd`

Use `TypedDict` for `SensitiveMatch` with keys: `category`, `severity`, `pattern`.

**Step 4: Run tests**

Run: `python -m pytest tests/test_fuzzing_tools.py -k "sensitive" -v`
Expected: All 6 PASS

**Step 5: Commit**

Message: `feat(fuzzing): add sensitive file pattern detection module`

---

## Task 4: Create permutation module

**Files:**
- Create: `workers/fuzzing_worker/permutation.py`
- Modify: `tests/test_fuzzing_tools.py`

**Step 1: Write failing tests**

Add to `tests/test_fuzzing_tools.py`:

- `test_permutation_generates_suffix_variants` — `generate_permutations(["dev"], "target.com")` contains `dev-api.target.com`, `dev-staging.target.com`
- `test_permutation_generates_prefix_variants` — contains `v1.api.target.com`, `v2.api.target.com`
- `test_permutation_swaps_separators` — `dev-api` generates `dev.api.target.com`
- `test_permutation_dedup_against_existing` — existing set filters out known domains
- `test_permutation_extracts_prefix` — `extract_prefix("dev.target.com", "target.com")` returns `"dev"`, returns None for base domain itself

**Step 2: Run to verify failure**

**Step 3: Write permutation.py**

Two functions:
- `extract_prefix(fqdn, base_domain) -> str | None` — strips `.base_domain` suffix
- `generate_permutations(prefixes, base_domain, existing=None) -> list[str]` — applies SUFFIXES (`-api`, `-admin`, `-staging`, `-test`, `-v2`, `-internal`, `-dev`, `-prod`, `-qa`, `-uat`), PREFIXES (`v1.`, `v2.`, `new.`, `old.`, `beta.`, `alpha.`), and separator swaps

**Step 4: Run tests — All 5 PASS**

**Step 5: Commit**

Message: `feat(fuzzing): add subdomain permutation generator`

---

## Task 5: Create FfufTool (Stage 1 — breadth)

**Files:**
- Create: `workers/fuzzing_worker/tools/ffuf_tool.py`
- Modify: `tests/test_fuzzing_tools.py`
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write failing tests**

Add to `tests/test_fuzzing_tools.py`:

- `test_ffuf_tool_parses_json_output` — parses sample ffuf JSON (`{"results": [...]}`)
- `test_ffuf_tool_builds_command_with_headers` — verifies `-rate`, `-H`, `-mc` flags
- `test_ffuf_tool_skips_on_cooldown` — mocked cooldown returns `skipped_cooldown: True`
- `test_ffuf_tool_execute_saves_assets` — mocked subprocess + DB helpers, verifies `_save_asset` called

Sample ffuf JSON for tests:
```json
{"results": [
  {"input": {"FUZZ": "admin"}, "status": 200, "length": 1234, "url": "https://acme.com/admin"},
  {"input": {"FUZZ": ".env"}, "status": 200, "length": 89, "url": "https://acme.com/.env"},
  {"input": {"FUZZ": "secret"}, "status": 403, "length": 199, "url": "https://acme.com/secret"}
]}
```

**Step 2: Run to verify failure**

**Step 3: Write ffuf_tool.py**

- `name = "ffuf"`, `weight_class = WeightClass.HEAVY`
- `_choose_wordlist(rate_limit)` — returns LARGE if `>= 50`, else SMALL
- `build_command(url, wordlist, rate_limit, headers, output_file)` — builds ffuf CLI args with `-u`, `-w`, `-o`, `-of json`, `-mc 200,204,301,302,307,401,403`, `-rate`, `-t`, `-H` per header
- `parse_output(raw)` — JSON parse, return `data.get("results", [])`
- `execute(...)` — cooldown check, get live URLs, per-URL: build cmd, run subprocess, parse, scope-check + save asset, check sensitive patterns (via `check_sensitive`), flag 401/403 as info-severity vuln, track discovered dirs in `shared_state` dict for feroxbuster handoff

Wordlist env vars: `WORDLIST_SMALL` (default `/app/wordlists/common.txt`), `WORDLIST_LARGE` (default `/app/wordlists/directory-list-2.3-medium.txt`).

**Step 4: Update tools/__init__.py** — add `FfufTool` import

**Step 5: Run tests — All 4 PASS**

**Step 6: Commit**

Message: `feat(fuzzing): add FfufTool for flat directory fuzzing`

---

## Task 6: Create FeroxbusterTool (Stage 1 — depth)

**Files:**
- Create: `workers/fuzzing_worker/tools/feroxbuster_tool.py`
- Modify: `tests/test_fuzzing_tools.py`
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write failing tests**

- `test_feroxbuster_parses_jsonl_output` — parses newline-delimited JSON lines
- `test_feroxbuster_builds_command` — verifies `--rate-limit`, `--depth`, `--json` flags
- `test_feroxbuster_execute_uses_discovered_dirs` — receives `discovered_dirs` kwarg, runs per-dir

Sample feroxbuster JSONL:
```
{"url": "https://acme.com/admin/config", "status": 200, "content_length": 500}
{"url": "https://acme.com/admin/users", "status": 200, "content_length": 1200}
```

**Step 2: Run to verify failure**

**Step 3: Write feroxbuster_tool.py**

- `name = "feroxbuster"`, `weight_class = WeightClass.HEAVY`
- `build_command(...)` — feroxbuster CLI with `-u`, `-w`, `-o`, `--json`, `--status-codes`, `--rate-limit`, `--threads`, `--depth 3`, `--headers`
- `parse_output(raw)` — line-by-line JSON parse, filter entries with `"url"` key
- `execute(...)` — receives `discovered_dirs` kwarg (from ffuf), runs feroxbuster on each dir, saves assets, checks sensitive patterns, flags 401/403

**Step 4: Update tools/__init__.py**

**Step 5: Run tests — All 3 PASS**

**Step 6: Commit**

Message: `feat(fuzzing): add FeroxbusterTool for recursive content discovery`

---

## Task 7: Create ExtensionFuzzTool (Stage 1 — backup permutations)

**Files:**
- Create: `workers/fuzzing_worker/tools/extension_fuzz_tool.py`
- Modify: `tests/test_fuzzing_tools.py`
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write failing tests**

- `test_extension_fuzz_filters_dynamic_files` — keeps `.php`, `.json`; drops `.png`, `.css`, extensionless
- `test_extension_fuzz_generates_variants` — `index.php` produces `index.php.bak`, `index.php.old`, `.index.php.swp`, `index.php~`

**Step 2: Run to verify failure**

**Step 3: Write extension_fuzz_tool.py**

- `name = "ffuf-ext"`, `weight_class = WeightClass.LIGHT`
- `DYNAMIC_EXTENSIONS` set: `.php`, `.asp`, `.aspx`, `.jsp`, `.py`, `.rb`, `.js`, `.json`, `.xml`, `.conf`, `.yml`, `.yaml`
- `BACKUP_EXTENSIONS` list: `.bak`, `.old`, `.swp`, `.orig`, `~`, `.temp`, `.save`, `.dist`
- `filter_dynamic_files(urls)` — returns URLs whose file extension is in DYNAMIC_EXTENSIONS
- `generate_variants(url)` — appends each backup ext + vim swap pattern
- `execute(...)` — receives `discovered_files` kwarg, filters to dynamic, generates all variants, writes to temp wordlist file, runs ffuf with `-u FUZZ -w <wordlist>`, parses results, saves assets + sensitive checks

**Step 4: Update tools/__init__.py**

**Step 5: Run tests — All 2 PASS**

**Step 6: Commit**

Message: `feat(fuzzing): add ExtensionFuzzTool for backup file permutations`

---

## Task 8: Create VhostFuzzTool (Stage 2)

**Files:**
- Create: `workers/fuzzing_worker/tools/vhost_fuzz_tool.py`
- Modify: `tests/test_fuzzing_tools.py`
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write failing tests**

- `test_vhost_fuzz_builds_command_per_ffuf_docs` — verifies `-H "Host: FUZZ.acme.com"`, `-fs <baseline>`, `-u https://<IP>`
- `test_vhost_fuzz_builds_combined_wordlist` — merges existing prefixes with DNS wordlist, deduplicates

**Step 2: Run to verify failure**

**Step 3: Write vhost_fuzz_tool.py**

- `name = "ffuf-vhost"`, `weight_class = WeightClass.HEAVY`
- `build_wordlist(existing_prefixes)` — merge with SecLists DNS list at `VHOST_WORDLIST` env var
- `build_command(ip, base_domain, wordlist, rate_limit, baseline_size, headers, output_file)` — per ffuf docs: `-u https://<IP> -H "Host: FUZZ.<base_domain>" -w <wl> -fs <baseline_size>`
- `_resolve_ip(domain)` — `socket.gethostbyname`
- `_get_baseline_size(ip, base_domain)` — aiohttp GET with random nonexistent Host, return body length
- `execute(...)` — gather existing domain prefixes from DB, build combined wordlist, resolve IP, get baseline, run ffuf, parse results, save vhosts as domain assets + Location rows, alert on sensitive keywords (`admin`, `internal`, `staging`, `debug`)

**Step 4: Update tools/__init__.py**

**Step 5: Run tests — All 2 PASS**

**Step 6: Commit**

Message: `feat(fuzzing): add VhostFuzzTool for virtual host discovery`

---

## Task 9: Create ArjunTool (Stage 3)

**Files:**
- Create: `workers/fuzzing_worker/tools/arjun_tool.py`
- Modify: `tests/test_fuzzing_tools.py`
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write failing tests**

- `test_arjun_parses_json_output` — parses `{"url": {"GET": ["id","debug"], "POST": ["token"]}}` into flat list of param dicts
- `test_arjun_builds_command` — verifies `--stable`, `--delay`, `-oJ`
- `test_arjun_flags_high_value_params` — `debug`, `admin`, `token`, `secret` in HIGH_VALUE_PARAMS set

Sample arjun output: `{"https://acme.com/api/users": {"GET": ["id", "debug", "admin"], "POST": ["token"]}}`

**Step 2: Run to verify failure**

**Step 3: Write arjun_tool.py**

- `name = "arjun"`, `weight_class = WeightClass.HEAVY`
- `HIGH_VALUE_PARAMS` set: `debug`, `admin`, `test`, `load_config`, `proxy`, `callback`, `token`, `secret`
- `build_command(url, rate_limit, headers, output_file)` — arjun CLI with `-u`, `-oJ`, `--stable`, `--delay <1000/rate_limit>ms`, `--headers`
- `parse_output(raw)` — JSON parse, flatten URL->method->params into list of `{"url", "method", "param_name"}` dicts
- `execute(...)` — queries `_get_all_url_assets`, runs arjun per URL, saves parameters via `_save_parameter`, creates high-severity vuln for HIGH_VALUE_PARAMS

**Step 4: Update tools/__init__.py**

**Step 5: Run tests — All 3 PASS**

**Step 6: Commit**

Message: `feat(fuzzing): add ArjunTool for HTTP parameter discovery`

---

## Task 10: Create HeaderFuzzTool (Stage 4)

**Files:**
- Create: `workers/fuzzing_worker/tools/header_fuzz_tool.py`
- Modify: `tests/test_fuzzing_tools.py`
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write failing tests**

- `test_header_fuzz_injection_headers_defined` — at least 5 headers, includes `X-Forwarded-For`, `X-Original-URL`
- `test_header_fuzz_content_types_defined` — includes `application/xml`, `text/yaml`
- `test_header_fuzz_detects_status_change` — 403->200 is significant; same status small body diff is not; same status large body diff (>10%) is significant
- `test_header_fuzz_skips_on_cooldown`

**Step 2: Run to verify failure**

**Step 3: Write header_fuzz_tool.py**

- `name = "header-fuzz"`, `weight_class = WeightClass.LIGHT`
- Uses `aiohttp` directly (no subprocess)
- `INJECTION_HEADERS` list of dicts: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `True-Client-IP: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Forwarded-Host: localhost`
- `CONTENT_TYPES` list: `application/xml`, `text/yaml`, `text/xml`, `application/x-www-form-urlencoded`
- `is_significant_deviation(baseline_status, baseline_size, test_status, test_size)` — True if status differs or body size diff >10%
- Sub-task A: per endpoint, baseline request, then one per injection header, compare
- Sub-task B: per endpoint, POST with XXE probe payload for XML content types, check for `xxe-canary` reflection or error indicators
- Rate limiting via `asyncio.Semaphore(rate_limit)`
- Severity: 403->200 bypass = high; body-only diff = low; XXE indicator = critical; verbose error = medium

**Step 4: Update tools/__init__.py**

**Step 5: Run tests — All 4 PASS**

**Step 6: Commit**

Message: `feat(fuzzing): add HeaderFuzzTool for header injection and content-type fuzzing`

---

## Task 11: Create pipeline.py

**Files:**
- Create: `workers/fuzzing_worker/pipeline.py`
- Modify: `tests/test_fuzzing_pipeline.py`

**Step 1: Write failing tests**

Add to `tests/test_fuzzing_pipeline.py`:

- `test_fuzzing_stages_defined_in_order` — 4 stages: `dir_fuzzing`, `vhost_fuzzing`, `param_discovery`, `header_fuzzing`
- `test_fuzzing_each_stage_has_tools` — every stage has at least one tool class
- `test_fuzzing_stage_tools_are_fuzzing_tool_subclasses` — all tool_classes subclass FuzzingTool
- `test_fuzzing_pipeline_skips_completed_stages` — mock `_get_completed_phase` returns `"vhost_fuzzing"`, verify only `param_discovery` and `header_fuzzing` run

**Step 2: Run to verify failure**

**Step 3: Write pipeline.py**

Mirror `workers/webapp_worker/pipeline.py` structure with these changes:
- 4 stages: `dir_fuzzing` [FfufTool, FeroxbusterTool, ExtensionFuzzTool], `vhost_fuzzing` [VhostFuzzTool], `param_discovery` [ArjunTool], `header_fuzzing` [HeaderFuzzTool]
- `_run_stage` — for `dir_fuzzing`, run tools sequentially with data chaining (ffuf -> feroxbuster -> extension fuzz via kwargs). Other stages run tools concurrently via `asyncio.gather`
- `_run_dir_fuzzing_stage` — special method: runs ffuf first (passes `shared_state` dict), then feroxbuster (passes `discovered_dirs` from shared_state), then extension fuzz (passes `discovered_files` from all URL assets)
- `_run_permutation_handoff` — post-pipeline: extracts domain prefixes, generates permutations, pushes batches of 100 to `recon_queue` with `"source": "fuzzing_permutation"`
- Checkpoint helpers identical to webapp: `_get_completed_phase`, `_update_phase`, `_mark_completed`
- No browser lifecycle management (unlike webapp)
- No HTTP client factory (tools manage their own)

**Step 4: Run tests — All 4 PASS**

**Step 5: Commit**

Message: `feat(fuzzing): add 4-stage pipeline with tool chaining and permutation handoff`

---

## Task 12: Create main.py

**Files:**
- Create: `workers/fuzzing_worker/main.py`
- Modify: `tests/test_fuzzing_pipeline.py`

**Step 1: Write failing test**

- `test_fuzzing_main_handle_message_creates_jobstate` — seeds Target, calls `handle_message`, verifies JobState row created with `status="RUNNING"`

**Step 2: Run to verify failure**

**Step 3: Write main.py**

Copy `workers/webapp_worker/main.py` with these changes:
- Logger name: `"fuzzing-worker"`
- Default container name: `"fuzzing-worker-unknown"`
- Queue: `"fuzzing_queue"`, group: `"fuzzing_group"`
- Import Pipeline from `workers.fuzzing_worker.pipeline`
- No `action` field processing (fuzzing has one action)

**Step 4: Run test — PASS**

**Step 5: Commit**

Message: `feat(fuzzing): add main.py queue listener and message handler`

---

## Task 13: Finalize tools/__init__.py

**Files:**
- Modify: `workers/fuzzing_worker/tools/__init__.py`

**Step 1: Write final exports**

Import all 6 tools: `FfufTool`, `FeroxbusterTool`, `ExtensionFuzzTool`, `VhostFuzzTool`, `ArjunTool`, `HeaderFuzzTool`. Set `__all__`.

**Step 2: Verify imports**

Run: `python -c "from workers.fuzzing_worker.tools import FfufTool, FeroxbusterTool, ExtensionFuzzTool, VhostFuzzTool, ArjunTool, HeaderFuzzTool; print('OK')"`

**Step 3: Commit**

Message: `feat(fuzzing): finalize tools package exports`

---

## Task 14: Create Dockerfile.fuzzing

**Files:**
- Create: `docker/Dockerfile.fuzzing`

**Step 1: Write Dockerfile**

Multi-stage build:
1. `go-builder` (golang:1.22-bookworm): `go install github.com/ffuf/ffuf/v2@latest`
2. `rust-builder` (rust:1.77-bookworm): `cargo install feroxbuster`
3. `py-builder` (python:3.10-slim-bookworm): `pip install --target=/py-tools arjun aiohttp`
4. `seclists` (debian:bookworm-slim): wget SecLists zip, extract `common.txt`, `directory-list-2.3-medium.txt`, `subdomains-top1million-5000.txt` to `/seclists/`
5. Runtime (python:3.10-slim-bookworm): apt `gcc libpq-dev`, copy binaries, copy py-tools, copy wordlists to `/app/wordlists`, install lib_webbh, copy worker source, smoke test import, entrypoint `python -m workers.fuzzing_worker.main`

**Step 2: Commit**

Message: `build(docker): add Dockerfile.fuzzing with ffuf, feroxbuster, arjun, and SecLists`

---

## Task 15: Run full test suite

**Step 1: Run all fuzzing tests**

Run: `python -m pytest tests/test_fuzzing_pipeline.py tests/test_fuzzing_tools.py -v`
Expected: All PASS

**Step 2: Run existing tests for regressions**

Run: `python -m pytest tests/ -v --timeout=30`
Expected: All PASS

**Step 3: Commit any fixes**

Message: `fix(fuzzing): resolve test issues`
