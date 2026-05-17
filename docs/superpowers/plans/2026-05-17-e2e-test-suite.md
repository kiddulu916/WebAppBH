# E2E Integration Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the entire mocked test suite with a live-stack e2e suite that exercises all 17 standard workers against `testphp.vulnweb.com`, monitoring every stage via SSE and asserting real DB results.

**Architecture:** A session-scoped `stack` fixture in `tests/conftest.py` starts the docker stack, then module-scoped `pipeline_result` fixtures (one per test file) POST a target, run the SSE-driven pipeline monitor, and yield `(target_id, PipelineReport)` shared by both tests in each file. Single-worker e2e playbooks in `playbooks.py` ensure each test only triggers the relevant worker.

**Tech Stack:** pytest + pytest-asyncio (`asyncio_mode=auto`), httpx (async HTTP + SSE streaming), subprocess (docker commands), Python 3.11+

---

## File Map

**Modified:**
- `shared/lib_webbh/playbooks.py` — add 11 single-worker `e2e_{worker}` playbooks

**Created:**
- `tests/pytest.ini`
- `tests/conftest.py`
- `tests/e2e/__init__.py`
- `tests/e2e/test_info_gathering.py`
- `tests/e2e/test_config_mgmt.py`
- `tests/e2e/test_identity_mgmt.py`
- `tests/e2e/test_authentication.py`
- `tests/e2e/test_authorization.py`
- `tests/e2e/test_session_mgmt.py`
- `tests/e2e/test_input_validation.py`
- `tests/e2e/test_error_handling.py`
- `tests/e2e/test_cryptography.py`
- `tests/e2e/test_business_logic.py`
- `tests/e2e/test_client_side.py`
- `tests/e2e/test_chain_worker.py`
- `tests/e2e/test_reporting_worker.py`
- `tests/e2e/test_reasoning_worker.py`
- `tests/e2e/test_sandbox_worker.py`
- `tests/e2e/test_proxy.py`
- `tests/e2e/test_callback.py`
- `.github/workflows/e2e.yml`

**Deleted:**
- All 219 existing files under `tests/` (see Task 1)

---

## Task 1: Delete existing test suite + add e2e playbooks

**Files:**
- Delete: entire `tests/` directory contents
- Modify: `shared/lib_webbh/playbooks.py`

- [ ] **Step 1: Delete all existing test files**

```bash
# From repo root
find tests/ -name "*.py" -delete
find tests/ -name "*.yml" -delete
find tests/ -type d -empty -delete
# On Windows PowerShell:
# Remove-Item -Recurse -Force tests\*
```

- [ ] **Step 2: Verify tests/ is empty**

```bash
ls tests/
# Expected: no files
```

- [ ] **Step 3: Add single-worker e2e playbooks to playbooks.py**

Open `shared/lib_webbh/playbooks.py`. Add after the `DEFAULT_PLAYBOOK` line (currently line 279):

```python
# ---------------------------------------------------------------------------
# E2E test playbooks — one worker at a time (for automated test suite)
# ---------------------------------------------------------------------------
_E2E_STANDALONE_WORKERS = [
    "info_gathering", "config_mgmt", "identity_mgmt", "authentication",
    "authorization", "session_mgmt", "input_validation", "error_handling",
    "cryptography", "business_logic", "client_side",
]

for _e2e_worker in _E2E_STANDALONE_WORKERS:
    BUILTIN_PLAYBOOKS[f"e2e_{_e2e_worker}"] = PlaybookConfig(
        name=f"e2e_{_e2e_worker}",
        description=f"E2E test playbook: runs only {_e2e_worker}",
        workers=_build_all_workers(
            disabled_workers=[w for w in _ALL_WORKERS if w != _e2e_worker],
        ),
    )
```

- [ ] **Step 4: Verify playbooks load without errors**

```bash
cd shared && python -c "from lib_webbh.playbooks import BUILTIN_PLAYBOOKS; print(list(BUILTIN_PLAYBOOKS.keys()))"
```

Expected output includes: `'e2e_info_gathering'`, `'e2e_config_mgmt'`, etc.

- [ ] **Step 5: Commit**

```bash
git add shared/lib_webbh/playbooks.py
git commit -m "feat(playbooks): add single-worker e2e test playbooks"
```

---

## Task 2: pytest.ini + conftest.py skeleton

**Files:**
- Create: `tests/pytest.ini`
- Create: `tests/conftest.py`
- Create: `tests/e2e/__init__.py`

- [ ] **Step 1: Create pytest.ini**

Create `tests/pytest.ini`:

```ini
[pytest]
asyncio_mode = auto
markers =
    e2e: marks tests as requiring the live docker stack (pass --e2e)
```

- [ ] **Step 2: Create tests/e2e/__init__.py**

```python
```
(empty file)

- [ ] **Step 3: Create tests/conftest.py skeleton with stack fixture**

```python
"""E2E test infrastructure: stack lifecycle, HTTP client, SSE monitor, helpers."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx
import pytest

_REPO_ROOT = Path(__file__).parent.parent
_BASE_URL = "http://localhost:8001"
_HEALTH_URL = f"{_BASE_URL}/api/v1/health"

LOG_IGNORE_PATTERNS = [
    "redis.exceptions.ConnectionError",
    "asyncpg.exceptions",
    "Connection refused",
    "Retrying",
]


# ---------------------------------------------------------------------------
# Pytest hooks
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption(
        "--e2e", action="store_true", default=False,
        help="Run e2e tests against the live docker stack",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--e2e"):
        skip = pytest.mark.skip(reason="pass --e2e to run against the live docker stack")
        for item in items:
            if "e2e" in item.keywords:
                item.add_marker(skip)


# ---------------------------------------------------------------------------
# Stack lifecycle helpers (synchronous — used in session-scoped fixture)
# ---------------------------------------------------------------------------

def _is_stack_running() -> bool:
    try:
        urllib.request.urlopen(_HEALTH_URL, timeout=2)
        return True
    except Exception:
        return False


def _wait_for_health(timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    delay = 1.0
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(_HEALTH_URL, timeout=5)
            return
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 15)
    raise TimeoutError(f"Stack did not become healthy within {timeout}s")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def stack(request):
    if not request.config.getoption("--e2e"):
        yield
        return

    already_running = _is_stack_running()
    if not already_running:
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml",
             "-f", "docker-compose.test.yml", "up", "-d", "--build"],
            check=True,
            cwd=_REPO_ROOT,
        )
        _wait_for_health(timeout=120)

    yield

    if not already_running:
        subprocess.run(
            ["docker", "compose", "down", "-v"],
            check=True,
            cwd=_REPO_ROOT,
        )
```

- [ ] **Step 4: Verify pytest collects with --e2e flag (no tests yet, should show 0 items)**

```bash
cd tests && pytest --e2e --collect-only 2>&1 | head -5
```

Expected: no errors, `0 items` collected.

- [ ] **Step 5: Commit**

```bash
git add tests/pytest.ini tests/conftest.py tests/e2e/__init__.py
git commit -m "feat(e2e): add pytest.ini, conftest skeleton, stack lifecycle fixture"
```

---

## Task 3: SSEMonitor + PipelineReport

**Files:**
- Modify: `tests/conftest.py` (append)

- [ ] **Step 1: Add PipelineReport, StageTimeoutError, and SSEMonitor to conftest.py**

Append to `tests/conftest.py` after the `stack` fixture:

```python
# ---------------------------------------------------------------------------
# SSE monitoring
# ---------------------------------------------------------------------------

class StageTimeoutError(Exception):
    def __init__(self, stage: str, elapsed: float):
        super().__init__(f"Stage '{stage}' timed out after {elapsed:.0f}s")
        self.stage = stage
        self.elapsed = elapsed


@dataclass
class PipelineReport:
    completed_stages: list[str] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    stage_durations: dict[str, float] = field(default_factory=dict)
    container_logs_clean: bool = True
    raw_events: list[dict] = field(default_factory=list)


_ERROR_KEYWORDS = ("error", "failed", "exception")


def _check_container_logs(container_name: str, tail: int = 500) -> bool:
    """Return True if no unexpected ERROR/Traceback lines appear in container logs."""
    try:
        result = subprocess.run(
            ["docker", "logs", container_name, "--tail", str(tail)],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return True  # can't check, assume clean

    combined = result.stdout + result.stderr
    for line in combined.splitlines():
        if "Traceback (most recent call last)" in line or \
           " ERROR " in line or " CRITICAL " in line:
            if not any(pat in line for pat in LOG_IGNORE_PATTERNS):
                return False
    return True


class SSEMonitor:
    """Drives stage-level e2e assertions by consuming the SSE event stream."""

    def __init__(self):
        self._api_key = _read_api_key()

    async def run(
        self,
        target_id: int,
        worker: str,
        stage_assertions: dict[str, Callable | None],
        stage_timeouts: dict[str, int],
        default_stage_timeout: int = 300,
    ) -> PipelineReport:
        report = PipelineReport()
        event_queue: asyncio.Queue[dict] = asyncio.Queue()

        async def _reader():
            async with httpx.AsyncClient(
                base_url=_BASE_URL,
                headers={"X-API-KEY": self._api_key},
                timeout=httpx.Timeout(None),
            ) as stream_client:
                async with stream_client.stream(
                    "GET", f"/api/v1/stream/{target_id}"
                ) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            try:
                                event = json.loads(line[6:])
                                await event_queue.put(event)
                            except json.JSONDecodeError:
                                pass
            await event_queue.put({"event": "_EOF"})

        reader_task = asyncio.create_task(_reader())
        try:
            for stage_name, assertion in stage_assertions.items():
                timeout_s = stage_timeouts.get(stage_name, default_stage_timeout)
                stage_start = time.monotonic()

                while True:
                    remaining = timeout_s - (time.monotonic() - stage_start)
                    if remaining <= 0:
                        raise StageTimeoutError(stage_name, time.monotonic() - stage_start)
                    try:
                        event = await asyncio.wait_for(event_queue.get(), timeout=remaining)
                    except asyncio.TimeoutError:
                        raise StageTimeoutError(stage_name, time.monotonic() - stage_start)

                    report.raw_events.append(event)
                    event_type = event.get("event", "")

                    if any(kw in event_type.lower() for kw in _ERROR_KEYWORDS):
                        report.errors.append(event)

                    if event_type == "_EOF":
                        return report

                    if event_type == "STAGE_COMPLETE" and event.get("stage") == stage_name:
                        report.completed_stages.append(stage_name)
                        report.stage_durations[stage_name] = time.monotonic() - stage_start
                        if assertion is not None:
                            await assertion(target_id)
                        break

            # Drain until PIPELINE_COMPLETE (up to 60s)
            try:
                while True:
                    event = await asyncio.wait_for(event_queue.get(), timeout=60)
                    if event.get("event") in ("PIPELINE_COMPLETE", "_EOF"):
                        break
            except asyncio.TimeoutError:
                pass

            report.container_logs_clean = _check_container_logs(worker)
        finally:
            reader_task.cancel()
            try:
                await reader_task
            except (asyncio.CancelledError, Exception):
                pass

        return report


@pytest.fixture(scope="module")
def sse_monitor():
    return SSEMonitor()
```

- [ ] **Step 2: Verify conftest.py imports cleanly**

```bash
cd tests && python -c "import conftest; print('ok')"
```

Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "feat(e2e): add SSEMonitor, PipelineReport, StageTimeoutError to conftest"
```

---

## Task 4: Shared helpers

**Files:**
- Modify: `tests/conftest.py` (append)

- [ ] **Step 1: Add helpers to conftest.py**

Append to `tests/conftest.py` after the `sse_monitor` fixture:

```python
# ---------------------------------------------------------------------------
# API key reader
# ---------------------------------------------------------------------------

def _read_api_key() -> str:
    key = os.environ.get("WEB_APP_BH_API_KEY", "")
    if key:
        return key
    env_file = _REPO_ROOT / "shared" / "config" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("WEB_APP_BH_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError("WEB_APP_BH_API_KEY not found in environment or shared/config/.env")


# ---------------------------------------------------------------------------
# HTTP client fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
async def client(stack):
    async with httpx.AsyncClient(
        base_url=_BASE_URL,
        headers={"X-API-KEY": _read_api_key(), "Content-Type": "application/json"},
        timeout=30.0,
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Target helpers
# ---------------------------------------------------------------------------

_DEFAULT_TARGET = "testphp.vulnweb.com"


async def create_target(
    client: httpx.AsyncClient,
    playbook: str,
    company: str,
    domain: str = _DEFAULT_TARGET,
) -> int:
    res = await client.post("/api/v1/targets", json={
        "company_name": company,
        "base_domain": domain,
        "playbook": playbook,
    })
    if res.status_code == 409:
        raise RuntimeError(
            f"409: another target is still active — previous test cleanup may have failed. "
            f"Response: {res.text}"
        )
    assert res.status_code == 201, f"create_target failed: {res.status_code} {res.text}"
    return res.json()["target_id"]


async def cleanup_target(client: httpx.AsyncClient, target_id: int) -> None:
    try:
        res = await client.delete(f"/api/v1/targets/{target_id}")
        if res.status_code not in (200, 204, 404):
            print(f"\nWARNING: cleanup_target({target_id}) returned {res.status_code}: {res.text}")
    except Exception as exc:
        print(f"\nWARNING: cleanup_target({target_id}) raised {exc}")


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

async def assert_assets(
    client: httpx.AsyncClient,
    target_id: int,
    min_count: int = 1,
    asset_type: str | None = None,
) -> list:
    params: dict = {"target_id": target_id}
    if asset_type:
        params["asset_type"] = asset_type
    res = await client.get("/api/v1/assets", params=params)
    assert res.status_code == 200, f"GET /api/v1/assets returned {res.status_code}"
    data = res.json()
    assert data["total"] >= min_count, (
        f"Expected ≥{min_count} assets (asset_type={asset_type!r}) for target {target_id}, "
        f"got {data['total']}"
    )
    return data["assets"]


async def assert_vulnerabilities(
    client: httpx.AsyncClient,
    target_id: int,
    min_count: int = 1,
) -> list:
    res = await client.get("/api/v1/vulnerabilities", params={"target_id": target_id})
    assert res.status_code == 200, f"GET /api/v1/vulnerabilities returned {res.status_code}"
    data = res.json()
    assert data["total"] >= min_count, (
        f"Expected ≥{min_count} vulnerabilities for target {target_id}, got {data['total']}"
    )
    return data["vulnerabilities"]


async def assert_job_completed(
    client: httpx.AsyncClient,
    target_id: int,
    container_name: str,
    last_stage: str,
) -> dict:
    res = await client.get("/api/v1/status", params={"target_id": target_id})
    assert res.status_code == 200
    jobs = res.json()["jobs"]
    job = next((j for j in jobs if j["container_name"] == container_name), None)
    assert job is not None, (
        f"No job_state row found for container '{container_name}', target {target_id}. "
        f"Known containers: {[j['container_name'] for j in jobs]}"
    )
    assert job["status"] == "COMPLETED", (
        f"Expected status=COMPLETED for '{container_name}', got {job['status']}"
    )
    assert job["current_phase"] == last_stage, (
        f"Expected current_phase='{last_stage}' for '{container_name}', "
        f"got '{job['current_phase']}'"
    )
    return job
```

- [ ] **Step 2: Move `_read_api_key` above `SSEMonitor.__init__` (it's called there)**

The `_read_api_key` function is currently appended after `SSEMonitor`, but `SSEMonitor.__init__` calls it. Move the `_read_api_key` definition to be the first helper defined in conftest.py — before the `SSEMonitor` class. Edit `conftest.py` so `_read_api_key` appears immediately after the `LOG_IGNORE_PATTERNS` list.

- [ ] **Step 3: Verify conftest.py is importable**

```bash
cd tests && python -c "import conftest; print('ok')"
```

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add tests/conftest.py
git commit -m "feat(e2e): add create_target, assert_assets, assert_vulnerabilities, assert_job_completed helpers"
```

---

## Task 5: test_info_gathering.py

**Files:**
- Create: `tests/e2e/test_info_gathering.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for info_gathering worker (WSTG-INFO-01 through INFO-10)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "info_gathering"
PLAYBOOK = "e2e_info_gathering"
LAST_STAGE = "map_application"

# Assertion callables receive (client, target_id). None = no-error only.
def _assets(target_id):
    async def _inner(client, tid):
        await assert_assets(client, tid)
    return _inner


STAGE_ASSERTIONS = {
    "search_engine_recon":   lambda c, tid: assert_assets(c, tid),
    "web_server_fingerprint": lambda c, tid: assert_assets(c, tid),
    "web_server_metafiles":  lambda c, tid: assert_assets(c, tid),
    "enumerate_applications": lambda c, tid: assert_assets(c, tid),
    "review_comments":       None,
    "identify_entry_points": lambda c, tid: assert_assets(c, tid),
    "aggregate_entry_points": lambda c, tid: assert_assets(c, tid),
    "map_execution_paths":   lambda c, tid: assert_assets(c, tid),
    "review_comments_deep":  None,
    "fingerprint_framework": lambda c, tid: assert_assets(c, tid),
    "map_architecture":      lambda c, tid: assert_assets(c, tid),
    "map_application":       lambda c, tid: assert_assets(c, tid),
}

STAGE_TIMEOUTS = {
    "search_engine_recon":    180,
    "web_server_fingerprint": 120,
    "web_server_metafiles":   120,
    "enumerate_applications": 180,
    "review_comments":        180,
    "identify_entry_points":  180,
    "aggregate_entry_points": 120,
    "map_execution_paths":    180,
    "review_comments_deep":   180,
    "fingerprint_framework":  120,
    "map_architecture":       120,
    "map_application":        120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-InfoGathering")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_info_gathering_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "info_gathering container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_info_gathering_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Run test dry (skip check, no stack needed)**

```bash
cd tests && pytest e2e/test_info_gathering.py -v 2>&1 | grep -E "SKIP|ERROR|PASS"
```

Expected: `SKIPPED` for both tests (no `--e2e` flag).

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_info_gathering.py
git commit -m "feat(e2e): add test_info_gathering pipeline e2e tests"
```

---

## Task 6: test_config_mgmt.py

**Files:**
- Create: `tests/e2e/test_config_mgmt.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for config_mgmt worker (WSTG-CONF-01 through CONF-11)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "config_mgmt"
PLAYBOOK = "e2e_config_mgmt"
LAST_STAGE = "cloud_storage"

STAGE_ASSERTIONS = {
    "network_config":          lambda c, tid: assert_assets(c, tid),
    "platform_config":         lambda c, tid: assert_assets(c, tid),
    "file_extension_handling": lambda c, tid: assert_assets(c, tid),
    "backup_files":            None,
    "api_discovery":           lambda c, tid: assert_assets(c, tid),
    "http_methods":            lambda c, tid: assert_assets(c, tid),
    "hsts_testing":            None,
    "rpc_testing":             None,
    "file_inclusion":          None,
    "subdomain_takeover":      None,
    "cloud_storage":           None,
}

STAGE_TIMEOUTS = {
    "network_config":          180,
    "platform_config":         120,
    "file_extension_handling": 120,
    "backup_files":            120,
    "api_discovery":           180,
    "http_methods":            120,
    "hsts_testing":            120,
    "rpc_testing":             120,
    "file_inclusion":          120,
    "subdomain_takeover":      180,
    "cloud_storage":           180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ConfigMgmt")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_config_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "config_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_config_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Verify skip behavior**

```bash
cd tests && pytest e2e/test_config_mgmt.py -v 2>&1 | grep -E "SKIP|ERROR"
```

Expected: `SKIPPED`.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_config_mgmt.py
git commit -m "feat(e2e): add test_config_mgmt pipeline e2e tests"
```

---

## Task 7: test_identity_mgmt.py

**Files:**
- Create: `tests/e2e/test_identity_mgmt.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for identity_mgmt worker (WSTG-IDNT-01 through IDNT-05)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "identity_mgmt"
PLAYBOOK = "e2e_identity_mgmt"
LAST_STAGE = "weak_username_policy"

STAGE_ASSERTIONS = {
    "role_definitions":       lambda c, tid: assert_assets(c, tid),
    "registration_process":   lambda c, tid: assert_assets(c, tid),
    "account_provisioning":   None,
    "account_enumeration":    None,
    "weak_username_policy":   None,
}

STAGE_TIMEOUTS = {
    "role_definitions":       120,
    "registration_process":   120,
    "account_provisioning":   120,
    "account_enumeration":    180,
    "weak_username_policy":   120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-IdentityMgmt")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_identity_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "identity_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_identity_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_identity_mgmt.py
git commit -m "feat(e2e): add test_identity_mgmt pipeline e2e tests"
```

---

## Task 8: test_authentication.py

**Files:**
- Create: `tests/e2e/test_authentication.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for authentication worker (WSTG-ATHN-01 through ATHN-10)."""
import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "authentication"
PLAYBOOK = "e2e_authentication"
LAST_STAGE = "multi_channel_auth"

STAGE_ASSERTIONS = {
    "credentials_transport": None,
    "default_credentials":   None,
    "lockout_mechanism":     None,
    "auth_bypass":           None,
    "remember_password":     None,
    "browser_cache":         None,
    "weak_password_policy":  None,
    "security_questions":    None,
    "password_change":       None,
    "multi_channel_auth":    None,
}

STAGE_TIMEOUTS = {
    "credentials_transport": 120,
    "default_credentials":   300,
    "lockout_mechanism":     180,
    "auth_bypass":           300,
    "remember_password":     120,
    "browser_cache":         120,
    "weak_password_policy":  120,
    "security_questions":    120,
    "password_change":       120,
    "multi_channel_auth":    120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-Authentication")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_authentication_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "authentication container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_authentication_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_authentication.py
git commit -m "feat(e2e): add test_authentication pipeline e2e tests"
```

---

## Task 9: test_authorization.py

**Files:**
- Create: `tests/e2e/test_authorization.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for authorization worker (WSTG-ATHZ-01 through ATHZ-04)."""
import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "authorization"
PLAYBOOK = "e2e_authorization"
LAST_STAGE = "idor"

STAGE_ASSERTIONS = {
    "directory_traversal": None,
    "authz_bypass":        None,
    "privilege_escalation": None,
    "idor":                None,
}

STAGE_TIMEOUTS = {
    "directory_traversal": 300,
    "authz_bypass":        300,
    "privilege_escalation": 300,
    "idor":                300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-Authorization")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_authorization_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "authorization container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_authorization_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_authorization.py
git commit -m "feat(e2e): add test_authorization pipeline e2e tests"
```

---

## Task 10: test_session_mgmt.py

**Files:**
- Create: `tests/e2e/test_session_mgmt.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for session_mgmt worker (WSTG-SESS-01 through SESS-09)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "session_mgmt"
PLAYBOOK = "e2e_session_mgmt"
LAST_STAGE = "session_hijacking"

STAGE_ASSERTIONS = {
    "session_scheme":      lambda c, tid: assert_assets(c, tid),
    "cookie_attributes":   lambda c, tid: assert_assets(c, tid),
    "session_fixation":    None,
    "exposed_variables":   None,
    "csrf":                None,
    "logout_functionality": None,
    "session_timeout":     None,
    "session_puzzling":    None,
    "session_hijacking":   None,
}

STAGE_TIMEOUTS = {
    "session_scheme":      180,
    "cookie_attributes":   120,
    "session_fixation":    180,
    "exposed_variables":   120,
    "csrf":                120,
    "logout_functionality": 120,
    "session_timeout":     120,
    "session_puzzling":    120,
    "session_hijacking":   180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-SessionMgmt")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_session_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "session_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_session_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_session_mgmt.py
git commit -m "feat(e2e): add test_session_mgmt pipeline e2e tests"
```

---

## Task 11: test_input_validation.py

**Files:**
- Create: `tests/e2e/test_input_validation.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for input_validation worker (WSTG-INPV-01 through INPV-19)."""
import pytest
from conftest import (
    assert_vulnerabilities, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "input_validation"
PLAYBOOK = "e2e_input_validation"
LAST_STAGE = "websocket_injection"

STAGE_ASSERTIONS = {
    "reflected_xss":        lambda c, tid: assert_vulnerabilities(c, tid),
    "stored_xss":           None,
    "http_verb_tampering":  None,
    "http_param_pollution": None,
    "sql_injection":        lambda c, tid: assert_vulnerabilities(c, tid),
    "ldap_injection":       None,
    "xml_injection":        None,
    "ssti":                 None,
    "xpath_injection":      None,
    "imap_smtp_injection":  None,
    "code_injection":       None,
    "command_injection":    None,
    "format_string":        None,
    "host_header_injection": None,
    "ssrf":                 None,
    "file_inclusion":       None,
    "buffer_overflow":      None,
    "http_smuggling":       None,
    "websocket_injection":  None,
}

STAGE_TIMEOUTS = {
    "reflected_xss":        600,
    "stored_xss":           600,
    "http_verb_tampering":  300,
    "http_param_pollution": 300,
    "sql_injection":        600,
    "ldap_injection":       300,
    "xml_injection":        300,
    "ssti":                 300,
    "xpath_injection":      300,
    "imap_smtp_injection":  300,
    "code_injection":       300,
    "command_injection":    300,
    "format_string":        300,
    "host_header_injection": 300,
    "ssrf":                 300,
    "file_inclusion":       300,
    "buffer_overflow":      300,
    "http_smuggling":       300,
    "websocket_injection":  300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-InputValidation")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_input_validation_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "input_validation container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_input_validation_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_input_validation.py
git commit -m "feat(e2e): add test_input_validation pipeline e2e tests"
```

---

## Task 12: test_error_handling.py

**Files:**
- Create: `tests/e2e/test_error_handling.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for error_handling worker (WSTG-ERRH-01 through ERRH-02)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "error_handling"
PLAYBOOK = "e2e_error_handling"
LAST_STAGE = "stack_traces"

STAGE_ASSERTIONS = {
    "error_codes":  lambda c, tid: assert_assets(c, tid),
    "stack_traces": None,
}

STAGE_TIMEOUTS = {
    "error_codes":  120,
    "stack_traces": 120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ErrorHandling")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_error_handling_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "error_handling container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_error_handling_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_error_handling.py
git commit -m "feat(e2e): add test_error_handling pipeline e2e tests"
```

---

## Task 13: test_cryptography.py

**Files:**
- Create: `tests/e2e/test_cryptography.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for cryptography worker (WSTG-CRYP-01 through CRYP-04)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "cryptography"
PLAYBOOK = "e2e_cryptography"
LAST_STAGE = "weak_crypto"

STAGE_ASSERTIONS = {
    "tls_testing":           lambda c, tid: assert_assets(c, tid),
    "padding_oracle":        None,
    "plaintext_transmission": None,
    "weak_crypto":           None,
}

STAGE_TIMEOUTS = {
    "tls_testing":           180,
    "padding_oracle":        300,
    "plaintext_transmission": 180,
    "weak_crypto":           180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-Cryptography")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_cryptography_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "cryptography container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_cryptography_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_cryptography.py
git commit -m "feat(e2e): add test_cryptography pipeline e2e tests"
```

---

## Task 14: test_business_logic.py

**Files:**
- Create: `tests/e2e/test_business_logic.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for business_logic worker (WSTG-BUSL-01 through BUSL-09)."""
import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "business_logic"
PLAYBOOK = "e2e_business_logic"
LAST_STAGE = "malicious_file_upload"

STAGE_ASSERTIONS = {
    "data_validation":          None,
    "request_forgery":          None,
    "integrity_checks":         None,
    "process_timing":           None,
    "rate_limiting":            None,
    "workflow_bypass":          None,
    "application_misuse":       None,
    "file_upload_validation":   None,
    "malicious_file_upload":    None,
}

STAGE_TIMEOUTS = {
    "data_validation":          300,
    "request_forgery":          300,
    "integrity_checks":         300,
    "process_timing":           300,
    "rate_limiting":            300,
    "workflow_bypass":          300,
    "application_misuse":       300,
    "file_upload_validation":   300,
    "malicious_file_upload":    300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-BusinessLogic")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_business_logic_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "business_logic container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_business_logic_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_business_logic.py
git commit -m "feat(e2e): add test_business_logic pipeline e2e tests"
```

---

## Task 15: test_client_side.py

**Files:**
- Create: `tests/e2e/test_client_side.py`

- [ ] **Step 1: Create test file**

```python
"""E2E tests for client_side worker (WSTG-CLNT-01 through CLNT-13)."""
import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "client_side"
PLAYBOOK = "e2e_client_side"
LAST_STAGE = "malicious_upload_client"

STAGE_ASSERTIONS = {
    "dom_xss":                           None,
    "clickjacking":                      None,
    "csrf_tokens":                       None,
    "csp_bypass":                        None,
    "html5_injection":                   None,
    "web_storage":                       None,
    "client_side_logic":                 None,
    "dom_based_injection":               None,
    "client_side_resource_manipulation": None,
    "client_side_auth":                  None,
    "xss_client_side":                   None,
    "css_injection":                     None,
    "malicious_upload_client":           None,
}

STAGE_TIMEOUTS = {
    "dom_xss":                           300,
    "clickjacking":                      120,
    "csrf_tokens":                       120,
    "csp_bypass":                        120,
    "html5_injection":                   120,
    "web_storage":                       120,
    "client_side_logic":                 120,
    "dom_based_injection":               120,
    "client_side_resource_manipulation": 120,
    "client_side_auth":                  120,
    "xss_client_side":                   300,
    "css_injection":                     120,
    "malicious_upload_client":           300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ClientSide")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_client_side_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "client_side container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_client_side_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_client_side.py
git commit -m "feat(e2e): add test_client_side pipeline e2e tests"
```

---

## Task 16: test_chain_worker.py

**Files:**
- Create: `tests/e2e/test_chain_worker.py`

The chain_worker needs findings from prior workers. This test uses `wide_recon`, waits
for `info_gathering` to complete first (providing data), then monitors chain_worker stages.
The SSEMonitor receives events from all workers interleaved — since chain_worker's stage
names (`data_collection`, `chain_evaluation`, etc.) are unique, the filter-by-name approach works.

- [ ] **Step 1: Create test file**

```python
"""E2E tests for chain_worker (depends on info_gathering findings).

Uses wide_recon so info_gathering populates the DB before chain_worker runs.
The SSEMonitor filters events by stage name — chain_worker stage names are unique
across all workers so interleaved events from other workers are transparently ignored.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "chain_worker"
PLAYBOOK = "wide_recon"
LAST_STAGE = "reporting"

# chain_worker stages only — SSEMonitor ignores events from other workers
STAGE_ASSERTIONS = {
    "data_collection":   None,
    "chain_evaluation":  None,
    "ai_chain_discovery": None,
    "chain_execution":   None,
    "reporting":         None,
}

STAGE_TIMEOUTS = {
    "data_collection":   300,
    "chain_evaluation":  300,
    "ai_chain_discovery": 600,
    "chain_execution":   900,
    "reporting":         300,
}

_INFO_GATHERING_TIMEOUT = 900  # wait up to 15 min for info_gathering to feed chain_worker


async def _wait_for_info_gathering(client, target_id: int, timeout: int = _INFO_GATHERING_TIMEOUT):
    """Poll until info_gathering reaches COMPLETED before chain_worker starts."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        ig_job = next((j for j in jobs if j["container_name"] == "info_gathering"), None)
        if ig_job and ig_job["status"] == "COMPLETED":
            return
        await asyncio.sleep(15)
    raise TimeoutError(f"info_gathering did not complete within {timeout}s (required by chain_worker)")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ChainWorker")
    await _wait_for_info_gathering(client, target_id)
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_chain_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "chain_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_chain_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_chain_worker.py
git commit -m "feat(e2e): add test_chain_worker pipeline e2e tests"
```

---

## Task 17: test_reporting_worker.py

**Files:**
- Create: `tests/e2e/test_reporting_worker.py`

> Note: playbooks.py registers this worker as `"reporting"` in `PIPELINE_STAGES`.
> Container name for log fetching is `"reporting_worker"`. Both are set as constants below.

- [ ] **Step 1: Create test file**

```python
"""E2E tests for reporting_worker (registered as 'reporting' in PIPELINE_STAGES).

Uses wide_recon so prior workers populate findings before reporting runs.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "reporting"           # playbooks.py key
CONTAINER = "reporting_worker" # docker container name (used for log fetch)
PLAYBOOK = "wide_recon"
LAST_STAGE = "export"

STAGE_ASSERTIONS = {
    "data_gathering": None,
    "deduplication":  None,
    "rendering":      None,
    "export":         lambda c, tid: assert_assets(c, tid),
}

STAGE_TIMEOUTS = {
    "data_gathering": 180,
    "deduplication":  120,
    "rendering":      300,
    "export":         120,
}

_PREREQ_TIMEOUT = 900


async def _wait_for_info_gathering(client, target_id: int, timeout: int = _PREREQ_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        ig = next((j for j in jobs if j["container_name"] == "info_gathering"), None)
        if ig and ig["status"] == "COMPLETED":
            return
        await asyncio.sleep(15)
    raise TimeoutError(f"info_gathering did not complete within {timeout}s")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ReportingWorker")
    await _wait_for_info_gathering(client, target_id)
    # SSEMonitor uses CONTAINER for log fetching
    report = await sse_monitor.run(target_id, CONTAINER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_reporting_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "reporting_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_reporting_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    # job_state container_name for reporting_worker
    await assert_job_completed(client, target_id, CONTAINER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_reporting_worker.py
git commit -m "feat(e2e): add test_reporting_worker pipeline e2e tests"
```

---

## Task 18: test_reasoning_worker.py

**Files:**
- Create: `tests/e2e/test_reasoning_worker.py`

Reasoning worker calls Ollama (`qwen3:14b` by default). Ollama must be running — `OLLAMA_AVAILABLE=true` is set in the CI environment and the stack includes the Ollama sidecar.

- [ ] **Step 1: Create test file**

```python
"""E2E tests for reasoning_worker (requires Ollama sidecar).

Uses wide_recon so info_gathering findings exist for the LLM to reason about.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "reasoning_worker"
PLAYBOOK = "wide_recon"
LAST_STAGE = "chain_hypothesis"

STAGE_ASSERTIONS = {
    "finding_correlation": None,
    "impact_analysis":     None,
    "chain_hypothesis":    None,
}

STAGE_TIMEOUTS = {
    "finding_correlation": 300,
    "impact_analysis":     300,
    "chain_hypothesis":    600,
}

_PREREQ_TIMEOUT = 900


async def _wait_for_info_gathering(client, target_id: int, timeout: int = _PREREQ_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        ig = next((j for j in jobs if j["container_name"] == "info_gathering"), None)
        if ig and ig["status"] == "COMPLETED":
            return
        await asyncio.sleep(15)
    raise TimeoutError(f"info_gathering did not complete within {timeout}s")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ReasoningWorker")
    await _wait_for_info_gathering(client, target_id)
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_reasoning_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "reasoning_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_reasoning_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_reasoning_worker.py
git commit -m "feat(e2e): add test_reasoning_worker pipeline e2e tests"
```

---

## Task 19: test_sandbox_worker.py, test_proxy.py, test_callback.py

These workers have no pipeline stages — they are infrastructure workers. Each test simply
asserts the container is running and its logs are clean.

**Files:**
- Create: `tests/e2e/test_sandbox_worker.py`
- Create: `tests/e2e/test_proxy.py`
- Create: `tests/e2e/test_callback.py`

- [ ] **Step 1: Create test_sandbox_worker.py**

```python
"""E2E health test for sandbox_worker (infrastructure worker, no pipeline stages)."""
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "sandbox_worker"


def test_sandbox_worker_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    assert result.stdout.strip() == "running", (
        f"Expected '{CONTAINER}' to be running, got: {result.stdout.strip()}"
    )


def test_sandbox_worker_logs_clean():
    result = subprocess.run(
        ["docker", "logs", CONTAINER, "--tail", "100"],
        capture_output=True, text=True, timeout=15,
    )
    combined = result.stdout + result.stderr
    bad_lines = [
        line for line in combined.splitlines()
        if ("Traceback (most recent call last)" in line
            or " ERROR " in line or " CRITICAL " in line)
        and "Retrying" not in line
    ]
    assert bad_lines == [], f"Unexpected errors in {CONTAINER} logs:\n" + "\n".join(bad_lines)
```

- [ ] **Step 2: Create test_proxy.py**

```python
"""E2E health test for proxy worker (infrastructure worker, no pipeline stages)."""
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "proxy"


def test_proxy_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    assert result.stdout.strip() == "running", (
        f"Expected '{CONTAINER}' to be running, got: {result.stdout.strip()}"
    )


def test_proxy_logs_clean():
    result = subprocess.run(
        ["docker", "logs", CONTAINER, "--tail", "100"],
        capture_output=True, text=True, timeout=15,
    )
    combined = result.stdout + result.stderr
    bad_lines = [
        line for line in combined.splitlines()
        if ("Traceback (most recent call last)" in line
            or " ERROR " in line or " CRITICAL " in line)
        and "Retrying" not in line
    ]
    assert bad_lines == [], f"Unexpected errors in {CONTAINER} logs:\n" + "\n".join(bad_lines)
```

- [ ] **Step 3: Create test_callback.py**

```python
"""E2E health test for callback worker (infrastructure worker, no pipeline stages)."""
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "callback"


def test_callback_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    assert result.stdout.strip() == "running", (
        f"Expected '{CONTAINER}' to be running, got: {result.stdout.strip()}"
    )


def test_callback_logs_clean():
    result = subprocess.run(
        ["docker", "logs", CONTAINER, "--tail", "100"],
        capture_output=True, text=True, timeout=15,
    )
    combined = result.stdout + result.stderr
    bad_lines = [
        line for line in combined.splitlines()
        if ("Traceback (most recent call last)" in line
            or " ERROR " in line or " CRITICAL " in line)
        and "Retrying" not in line
    ]
    assert bad_lines == [], f"Unexpected errors in {CONTAINER} logs:\n" + "\n".join(bad_lines)
```

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_sandbox_worker.py tests/e2e/test_proxy.py tests/e2e/test_callback.py
git commit -m "feat(e2e): add container health tests for sandbox_worker, proxy, callback"
```

---

## Task 20: GitHub Actions workflow

**Files:**
- Create: `.github/workflows/e2e.yml`

- [ ] **Step 1: Create workflow directory if it doesn't exist**

```bash
mkdir -p .github/workflows
```

- [ ] **Step 2: Create .github/workflows/e2e.yml**

```yaml
name: E2E Test Suite

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 120

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install test dependencies
        run: pip install pytest pytest-asyncio httpx

      - name: Start stack
        run: |
          docker compose \
            -f docker-compose.yml \
            -f docker-compose.test.yml \
            up -d --build
        env:
          OLLAMA_AVAILABLE: "true"

      - name: Wait for orchestrator health
        run: |
          for i in $(seq 1 30); do
            curl -sf http://localhost:8001/api/v1/health && exit 0
            echo "Waiting for stack... attempt $i"
            sleep 10
          done
          echo "Stack did not become healthy" && exit 1

      - name: Run e2e suite
        run: pytest tests/e2e/ --e2e -v --timeout=7200
        env:
          WEB_APP_BH_API_KEY: ${{ secrets.WEB_APP_BH_API_KEY }}
          OLLAMA_AVAILABLE: "true"

      - name: Dump container logs on failure
        if: failure()
        run: docker compose logs --tail=200

      - name: Tear down stack
        if: always()
        run: docker compose down -v
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/e2e.yml
git commit -m "ci: add GitHub Actions e2e workflow"
```

---

## Self-Review Notes

**Spec coverage check:**
- ✅ Section 2 (file structure): all 20 files covered across tasks
- ✅ Section 3 (stack fixture): Task 2 — lifecycle, health wait, yield, teardown
- ✅ Section 3.3 (SSEMonitor): Task 3 — full implementation with per-stage timeouts
- ✅ Section 3.4 (helpers): Task 4 — create_target, assert_assets, assert_vulnerabilities, assert_job_completed, cleanup_target
- ✅ Section 4 (per-worker pattern): Tasks 5-18 — pipeline_result fixture + 2 tests per file
- ✅ Section 5 (worker assertion tables): baked into each task's STAGE_ASSERTIONS dict
- ✅ Section 6 (error detection): SSEMonitor collects error events + _check_container_logs
- ✅ Section 7 (timeouts + CI): STAGE_TIMEOUTS per worker + Task 20 workflow
- ✅ Section 8 (target): `testphp.vulnweb.com` as default, `TEST_TARGET_DOMAIN` env override in `create_target` if needed
- ✅ Section 9 (what gets deleted): Task 1

**Potential issues to watch during implementation:**
1. The actual docker container names (e.g., `info_gathering` vs `webbh-info_gathering-1`) — run `docker ps` after stack start and verify container names match what `_check_container_logs` passes to `docker logs`.
2. The `DELETE /api/v1/targets/{id}` endpoint kills running containers — verify cleanup completes before next test's `create_target` to avoid 409.
3. `wide_recon` tests (chain_worker, reporting_worker, reasoning_worker) use all workers — run these last to avoid the long wait impacting earlier fast tests. pytest runs files alphabetically by default; rename files with a `z_` prefix if ordering matters.
