# Integration Test Suite — Design Spec

**Date:** 2026-05-16
**Status:** Approved
**Scope:** Replace the entire mocked test suite with a live-stack e2e suite that exercises all 17 standard workers against a real target.

---

## 1. Goal

Delete all 219 existing test files (mocked SQLite + AsyncMock-based) and replace them with a single e2e test suite that:

- Starts the docker stack automatically via `conftest.py`
- Runs every worker pipeline against `testphp.vulnweb.com`
- Monitors each stage via the SSE event stream as it executes
- Asserts stage-specific DB results via the orchestrator API after each `STAGE_COMPLETE` event
- Detects errors via SSE error events AND container log scanning
- Tears down cleanly after each run

**Workers covered:** all 17 active workers except `mobile_worker` (excluded — will get its own framework later).

---

## 2. File Structure

Delete everything in `tests/`. Replace with:

```
tests/
  conftest.py              # session stack fixture, SSEMonitor, shared helpers
  pytest.ini               # asyncio_mode=auto, --e2e flag, e2e marker
  e2e/
    __init__.py
    test_info_gathering.py
    test_config_mgmt.py
    test_identity_mgmt.py
    test_authentication.py
    test_authorization.py
    test_session_mgmt.py
    test_input_validation.py
    test_error_handling.py
    test_cryptography.py
    test_business_logic.py
    test_client_side.py
    test_chain_worker.py
    test_reporting_worker.py
    test_reasoning_worker.py
    test_sandbox_worker.py
    test_proxy.py
    test_callback.py
```

`reasoning_worker` runs unconditionally — Ollama is included in the stack with `OLLAMA_AVAILABLE=true`.

---

## 3. Stack Fixture (`tests/conftest.py`)

### 3.1 Stack lifecycle (session-scoped)

```python
@pytest.fixture(scope="session", autouse=True)
async def stack():
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml",
         "-f", "docker-compose.test.yml", "up", "-d", "--build"],
        check=True,
    )
    _wait_for_health("http://localhost:8001/api/v1/health", timeout=120)
    yield
    subprocess.run(["docker", "compose", "down", "-v"], check=True)
```

`_wait_for_health` polls with exponential backoff (1s → 2s → 4s … up to 120s total). Once the orchestrator responds 200, Postgres and Redis are guaranteed up (orchestrator health check verifies both).

Tests are skipped globally if `--e2e` flag is not passed.

### 3.2 HTTP client (module-scoped)

```python
@pytest.fixture(scope="module")
async def client():
    api_key = _read_api_key()   # reads from shared/config/.env
    async with httpx.AsyncClient(
        base_url="http://localhost:8001",
        headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
        timeout=30,
    ) as c:
        yield c
```

### 3.3 `SSEMonitor` and `sse_monitor` fixture

Core class that drives stage-level test execution. A module-scoped `sse_monitor` pytest fixture (defined in `conftest.py`) instantiates `SSEMonitor` with the shared `client` and yields it — test functions receive it directly via dependency injection.

Interface:

```python
@dataclass
class PipelineReport:
    completed_stages: list[str]
    errors: list[dict]            # full payloads of any error events
    stage_durations: dict[str, float]
    container_logs_clean: bool
    raw_events: list[dict]        # all events, for debugging

class SSEMonitor:
    async def run(
        self,
        target_id: int,
        worker: str,
        stage_assertions: dict[str, Callable],
        stage_timeouts: dict[str, int],
        default_stage_timeout: int = 300,
    ) -> PipelineReport
```

**Execution loop:**
1. Opens `httpx.AsyncClient.stream("GET", f"/api/v1/stream/{target_id}")`
2. Parses each SSE line into a typed event dict
3. On `STAGE_COMPLETE`:
   - Records duration
   - Calls `stage_assertions[stage_name](client, target_id)` if an assertion is defined
   - Verifies `job_state.current_phase` updated to the stage name
4. On any event where `event_type` contains `"error"`, `"failed"`, or `"exception"`: appends to `errors` list
5. On `PIPELINE_COMPLETE`: fetches container logs via `docker logs {worker}`, scans for `ERROR` or `Traceback`, sets `container_logs_clean`, closes stream
6. Enforces per-stage timeout: if no `STAGE_COMPLETE` arrives within `stage_timeouts[stage]`, raises `StagetimeoutError` naming the stuck stage

### 3.4 Shared helpers

```python
async def create_target(client, domain: str, playbook: str, company: str) -> int
    # POST /api/v1/targets, assert 201, return target_id

async def assert_min_rows(client, endpoint: str, target_id: int, min_count=1, **filters) -> list
    # GET endpoint, filter by target_id + filters, assert len >= min_count, return rows

async def cleanup_target(client, target_id: int) -> None
    # DELETE or deactivate target; logs warning on failure, never fails test
```

`cleanup_target` is called by an autouse function-scoped fixture after every test.

---

## 4. Per-Worker Test Pattern

Every test file defines three module-level dicts and two test functions.

### 4.1 Module-level constants

```python
WORKER = "info_gathering"
PLAYBOOK = "wide_recon"

STAGE_ASSERTIONS: dict[str, Callable] = {
    "search_engine_recon":   lambda c, tid: assert_min_rows(c, "/api/v1/assets", tid),
    "web_server_fingerprint": lambda c, tid: assert_min_rows(c, "/api/v1/assets", tid),
    # ... one entry per stage; stages with uncertain output on testphp use None
}

STAGE_TIMEOUTS: dict[str, int] = {
    "search_engine_recon": 180,
    "web_server_fingerprint": 120,
    # ... per stage in seconds
}
```

Stages where output on `testphp.vulnweb.com` is legitimately uncertain (e.g., `review_comments` may find nothing) use `None` as the assertion — SSE error monitoring still applies, but no DB row count is asserted.

### 4.2 Test functions (two per file)

**`test_{worker}_pipeline_stages`** — the primary test:
```python
async def test_info_gathering_pipeline_stages(client, sse_monitor):
    target_id = await create_target(client, "testphp.vulnweb.com", PLAYBOOK, "E2E-InfoGathering")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)

    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "Worker container logs contain ERROR/Traceback"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )
```

**`test_{worker}_job_state`** — verifies checkpoint state after pipeline completes:
```python
async def test_info_gathering_job_state(client):
    target_id = await create_target(client, "testphp.vulnweb.com", PLAYBOOK, "E2E-InfoGathering-JS")
    await _wait_pipeline_complete(client, target_id, timeout=900)

    status = await client.get(f"/api/v1/status?target_id={target_id}")
    job = status.json()["job_state"]
    assert job["status"] == "COMPLETED"
    assert job["current_phase"] == LAST_STAGE   # defined as module constant
```

---

## 5. Worker-Specific Assertion Tables

### `info_gathering` (12 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `search_engine_recon` | `assets` ≥ 1 | 180s |
| `web_server_fingerprint` | `assets` ≥ 1 (`asset_type=header`) | 120s |
| `web_server_metafiles` | `assets` ≥ 1 | 120s |
| `enumerate_applications` | `assets` ≥ 1 (`asset_type=url`) | 180s |
| `review_comments` | none (uncertain) | 180s |
| `identify_entry_points` | `assets` ≥ 1 | 180s |
| `aggregate_entry_points` | `assets` ≥ 1 | 120s |
| `map_execution_paths` | `assets` ≥ 1 | 180s |
| `review_comments_deep` | none (uncertain) | 180s |
| `fingerprint_framework` | `assets` ≥ 1 | 120s |
| `map_architecture` | `assets` ≥ 1 | 120s |
| `map_application` | `assets` ≥ 1 | 120s |

### `config_mgmt` (11 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `network_config` | `assets` ≥ 1 | 180s |
| `platform_config` | `assets` ≥ 1 | 120s |
| `file_extension_handling` | `assets` ≥ 1 | 120s |
| `backup_files` | none (uncertain) | 120s |
| `api_discovery` | `assets` ≥ 1 | 180s |
| `http_methods` | `assets` ≥ 1 | 120s |
| `hsts_testing` | none (uncertain) | 120s |
| `rpc_testing` | none (uncertain) | 120s |
| `file_inclusion` | none (uncertain) | 120s |
| `subdomain_takeover` | none (uncertain) | 180s |
| `cloud_storage` | none (uncertain) | 180s |

### `identity_mgmt` (5 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `role_definitions` | `assets` ≥ 1 | 120s |
| `registration_process` | `assets` ≥ 1 | 120s |
| `account_provisioning` | none (uncertain) | 120s |
| `account_enumeration` | none (uncertain) | 180s |
| `weak_username_policy` | none (uncertain) | 120s |

### `authentication` (10 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `credentials_transport` | `vulnerabilities` ≥ 0 (pipeline no-error only) | 120s |
| `default_credentials` | `vulnerabilities` ≥ 0 | 300s |
| `lockout_mechanism` | none (uncertain) | 180s |
| `auth_bypass` | none (uncertain) | 300s |
| `remember_password` | none (uncertain) | 120s |
| `browser_cache` | none (uncertain) | 120s |
| `weak_password_policy` | none (uncertain) | 120s |
| `security_questions` | none (uncertain) | 120s |
| `password_change` | none (uncertain) | 120s |
| `multi_channel_auth` | none (uncertain) | 120s |

### `authorization` (4 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `directory_traversal` | none (uncertain) | 300s |
| `authz_bypass` | none (uncertain) | 300s |
| `privilege_escalation` | none (uncertain) | 300s |
| `idor` | none (uncertain) | 300s |

### `session_mgmt` (9 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `session_scheme` | `assets` ≥ 1 | 180s |
| `cookie_attributes` | `assets` ≥ 1 | 120s |
| `session_fixation` | none (uncertain) | 180s |
| `exposed_variables` | none (uncertain) | 120s |
| `csrf` | none (uncertain) | 120s |
| `logout_functionality` | none (uncertain) | 120s |
| `session_timeout` | none (uncertain) | 120s |
| `session_puzzling` | none (uncertain) | 120s |
| `session_hijacking` | none (uncertain) | 180s |

### `input_validation` (19 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `reflected_xss` | `vulnerabilities` ≥ 1 (testphp is known-vulnerable) | 600s |
| `stored_xss` | `vulnerabilities` ≥ 0 | 600s |
| `http_verb_tampering` | none (uncertain) | 300s |
| `http_param_pollution` | none (uncertain) | 300s |
| `sql_injection` | `vulnerabilities` ≥ 1 (testphp is known-vulnerable) | 600s |
| `ldap_injection` | none (uncertain) | 300s |
| `xml_injection` | none (uncertain) | 300s |
| `ssti` | none (uncertain) | 300s |
| `xpath_injection` | none (uncertain) | 300s |
| `imap_smtp_injection` | none (uncertain) | 300s |
| `code_injection` | none (uncertain) | 300s |
| `command_injection` | none (uncertain) | 300s |
| `format_string` | none (uncertain) | 300s |
| `host_header_injection` | none (uncertain) | 300s |
| `ssrf` | none (uncertain) | 300s |
| `file_inclusion` | none (uncertain) | 300s |
| `buffer_overflow` | none (uncertain) | 300s |
| `http_smuggling` | none (uncertain) | 300s |
| `websocket_injection` | none (uncertain) | 300s |

### `error_handling` (2 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `error_codes` | `assets` ≥ 1 (testphp exposes error pages) | 120s |
| `stack_traces` | none (uncertain) | 120s |

### `cryptography` (4 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `tls_testing` | `assets` ≥ 1 | 180s |
| `padding_oracle` | none (uncertain) | 300s |
| `plaintext_transmission` | none (uncertain) | 180s |
| `weak_crypto` | none (uncertain) | 180s |

### `business_logic` (9 stages)

All stages: `none (uncertain)`, timeout 300s. Pipeline-completes-without-error is the assertion.

### `client_side` (13 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `dom_xss` | `vulnerabilities` ≥ 0 | 300s |
| `clickjacking` | none (uncertain) | 120s |
| `csrf_tokens` | none (uncertain) | 120s |
| `csp_bypass` | none (uncertain) | 120s |
| All others | none (uncertain) | 300s |

### `chain_worker` (5 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `data_collection` | `chain_findings` ≥ 1 (if prior workers ran) | 300s |
| `chain_evaluation` | `chain_findings` ≥ 1 | 300s |
| `ai_chain_discovery` | none (uncertain) | 600s |
| `chain_execution` | none (uncertain) | 900s |
| `reporting` | none (uncertain) | 300s |

### `reporting_worker` (4 stages)

> **Naming note:** `playbooks.py` registers this worker as `"reporting"` in `PIPELINE_STAGES`. The actual container and worker directory is `reporting_worker`. The `WORKER` constant in `test_reporting_worker.py` must use `"reporting"` to match the playbook key, but the container name for log fetching is `"reporting_worker"`. Both are documented as module-level constants in the test file.

| Stage | Assertion | Timeout |
|---|---|---|
| `data_gathering` | none (uncertain) | 180s |
| `deduplication` | none (uncertain) | 120s |
| `rendering` | none (uncertain) | 300s |
| `export` | `assets` ≥ 1 (report artifact) | 120s |

### `reasoning_worker` (3 stages)

| Stage | Assertion | Timeout |
|---|---|---|
| `finding_correlation` | none (uncertain) | 300s |
| `impact_analysis` | none (uncertain) | 300s |
| `chain_hypothesis` | none (uncertain) | 600s |

### `sandbox_worker`, `proxy`, `callback`

These workers have no entries in `PIPELINE_STAGES` and no stage definitions in `worker-stages.ts`. They are infrastructure/utility workers, not playbook-driven pipeline workers. They cannot be triggered via a standard `POST /api/v1/targets` + playbook flow.

Each gets a **container health test** instead of a pipeline test:
1. Assert the container is running: `docker inspect {container_name} --format '{{.State.Status}}'` returns `"running"`
2. Assert container logs are clean (no `ERROR` or `Traceback` within the last 100 lines at idle)

No SSE stream, no target creation, no stage assertions. This verifies the service starts and stays healthy without crashing at idle.

### `chain_worker` — data dependency

`chain_worker`'s `data_collection` stage reads from findings produced by prior workers. Since tests run independently, `chain_worker`'s test must POST a target with the `wide_recon` playbook and wait for `info_gathering` to complete first (polling `job_state` for `info_gathering` container to reach `COMPLETED`), then poll for `chain_worker` to start and complete. This ordering is enforced within the single `test_chain_worker.py` file — it is not a cross-file dependency. The `data_collection` assertion is `none (uncertain)` rather than `chain_findings ≥ 1` since findings depend on what info_gathering discovered.

---

## 6. Error Detection

Two parallel channels, both required to pass:

**Channel 1 — SSE events:** `SSEMonitor` flags any event where `event_type` contains `"error"`, `"failed"`, or `"exception"`. Collected in `PipelineReport.errors`. Test fails if `errors != []`.

**Channel 2 — Container logs:** After `PIPELINE_COMPLETE`, `SSEMonitor` runs `docker logs {worker_container_name} --tail 500` and scans for lines containing `ERROR`, `Traceback`, or `CRITICAL`. Any match sets `container_logs_clean = False`. Expected noise (e.g., connection retries that resolve) is filtered by a configurable `LOG_IGNORE_PATTERNS` list in `conftest.py`.

---

## 7. Timeouts and CI

**Per-stage timeouts** are defined per worker in each test file's `STAGE_TIMEOUTS` dict. `SSEMonitor` raises `StageTimeoutError(stage_name, elapsed)` if a stage takes longer than its timeout — this gives immediate signal about where the pipeline hung rather than a global timeout with no context.

**Running locally:**
```bash
# Full suite (~45–90 min depending on tool speed)
pytest tests/e2e/ --e2e -v

# Single worker
pytest tests/e2e/test_info_gathering.py --e2e -v
```

The `--e2e` flag is required (registered in `pytest.ini`). Without it: all tests skip with `"pass --e2e to run against the live docker stack"`.

**`pytest.ini`:**
```ini
[pytest]
asyncio_mode = auto
markers =
    e2e: marks tests as requiring the live docker stack (pass --e2e)
```

**GitHub Actions (`.github/workflows/e2e.yml`):**
```yaml
jobs:
  e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v4
      - name: Start stack
        run: docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
      - name: Install test deps
        run: pip install pytest pytest-asyncio httpx
      - name: Run e2e suite
        run: pytest tests/e2e/ --e2e -v --timeout=7200
        env:
          OLLAMA_AVAILABLE: "true"
      - name: Dump logs on failure
        if: failure()
        run: docker compose logs --tail=200
      - name: Tear down
        if: always()
        run: docker compose down -v
```

---

## 8. Target

**Primary target:** `testphp.vulnweb.com` — intentionally vulnerable PHP application maintained by Acunetix. Known to contain XSS, SQLi, and other OWASP Top 10 vulnerabilities, making it suitable for asserting that attack-oriented workers produce real findings.

**Fallback:** If `TEST_TARGET_DOMAIN` env var is set, all workers use that domain instead. Allows pointing at alternative targets without code changes.

---

## 9. What Gets Deleted

Everything in `tests/` except the new files listed in Section 2. This includes:
- All 219 existing Python test files
- `tests/conftest.py`, `tests/conftest_orchestrator.py`
- `tests/_patch_logger.py`, `tests/_stage2_helpers.py`
- `tests/integration/` directory
- Existing `tests/e2e/` directory (all three files are already skipped/legacy)
- All `__init__.py` files (replaced by new ones)

The `docker-compose.test.yml` at repo root is **kept** (it enables `ENABLE_TEST_SEED=true` and relaxes rate limits). The `tests/integration/docker-compose.test.yml` is deleted.
