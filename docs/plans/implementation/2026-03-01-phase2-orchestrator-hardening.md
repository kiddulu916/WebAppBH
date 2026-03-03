# Phase 2 Orchestrator Hardening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 16 issues identified in the Phase 2 orchestrator audit — bugs, security gaps, spec gaps, and code quality.

**Architecture:** All fixes apply to the existing three-file orchestrator (`main.py`, `event_engine.py`, `worker_manager.py`). Tests use SQLite in-memory for DB, mocked Docker client, and FastAPI's async test client. No new modules — only modifications and test files.

**Tech Stack:** FastAPI, SQLAlchemy async, pytest-asyncio, httpx (test client), unittest.mock

**Design doc:** `docs/plans/design/2026-03-01-phase2-orchestrator-hardening-design.md`

---

### Task 1: Set up orchestrator test infrastructure

**Files:**
- Modify: `orchestrator/requirements.txt`
- Create: `tests/conftest_orchestrator.py`
- Create: `tests/test_worker_manager.py`

This task establishes shared fixtures and mocks used by all subsequent tasks. The orchestrator tests need:
- SQLite in-memory DB with tables created (reuse existing pattern from `tests/test_database.py`)
- A mocked `docker.DockerClient` for `worker_manager` tests
- A FastAPI async test client for endpoint tests

**Step 1: Add test dependencies to requirements**

Add `httpx` to the orchestrator's requirements (needed for FastAPI TestClient):

```
# orchestrator/requirements.txt — append:
httpx>=0.27
```

**Step 2: Create shared orchestrator fixtures**

```python
# tests/conftest_orchestrator.py
"""Shared fixtures for orchestrator tests.

Import this module's fixtures via conftest.py or direct import in test files.
"""

import os
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Force SQLite for tests before any lib_webbh import
os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

from lib_webbh.database import get_engine, get_session, Base, Target, Asset, Location, Parameter, CloudAsset, JobState, Alert


@pytest_asyncio.fixture
async def db():
    """Create all tables in a fresh SQLite in-memory DB."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    """Insert a target and return its ID."""
    async with get_session() as session:
        t = Target(company_name="AuditCorp", base_domain="auditcorp.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def mock_docker_client():
    """Return a mocked docker.DockerClient."""
    client = MagicMock()
    client.containers = MagicMock()
    return client


@pytest.fixture
def mock_worker_manager():
    """Patch all worker_manager async functions to no-ops."""
    with patch("orchestrator.event_engine.worker_manager") as wm:
        wm.start_worker = AsyncMock(return_value="fake-container-id")
        wm.stop_worker = AsyncMock(return_value=True)
        wm.restart_worker = AsyncMock(return_value=True)
        wm.pause_worker = AsyncMock(return_value=True)
        wm.unpause_worker = AsyncMock(return_value=True)
        wm.kill_worker = AsyncMock(return_value=True)
        wm.should_queue = AsyncMock(return_value=False)
        wm.get_container_status = AsyncMock(return_value=None)
        yield wm
```

**Step 3: Write a smoke test for `worker_manager` mocking**

```python
# tests/test_worker_manager.py
"""Tests for orchestrator.worker_manager."""

import os
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import dataclass

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from orchestrator.worker_manager import (
    check_resources,
    should_queue,
    ContainerInfo,
    ResourceSnapshot,
)


@pytest.mark.asyncio
async def test_check_resources_returns_snapshot():
    with patch("orchestrator.worker_manager.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 50.0
        mock_mem = MagicMock()
        mock_mem.percent = 60.0
        mock_psutil.virtual_memory.return_value = mock_mem
        snap = await check_resources()
        assert isinstance(snap, ResourceSnapshot)
        assert snap.cpu_percent == 50.0
        assert snap.memory_percent == 60.0
        assert snap.is_healthy is True


@pytest.mark.asyncio
async def test_should_queue_returns_false_when_healthy():
    with patch("orchestrator.worker_manager.check_resources") as mock_cr:
        mock_cr.return_value = ResourceSnapshot(cpu_percent=50.0, memory_percent=60.0, is_healthy=True)
        result = await should_queue()
        assert result is False


@pytest.mark.asyncio
async def test_should_queue_returns_true_when_unhealthy():
    with patch("orchestrator.worker_manager.check_resources") as mock_cr:
        mock_cr.return_value = ResourceSnapshot(cpu_percent=90.0, memory_percent=90.0, is_healthy=False)
        result = await should_queue()
        assert result is True
```

**Step 4: Run tests to verify infrastructure works**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_worker_manager.py -v`
Expected: 3 PASS

**Step 5: Commit**

```bash
git add orchestrator/requirements.txt tests/conftest_orchestrator.py tests/test_worker_manager.py
git commit -m "test: add orchestrator test infrastructure and worker_manager tests"
```

---

### Task 2: Fix status mappings + expose unpause (Fixes 1, 8)

**Files:**
- Modify: `orchestrator/main.py:193-217`
- Create: `tests/test_main.py`

These two fixes touch the same code block in `/control` — the action map and status map.

**Step 1: Write failing tests**

```python
# tests/test_main.py
"""Tests for orchestrator.main — FastAPI endpoints."""

import os
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from lib_webbh.database import get_engine, Base, get_session, Target, JobState

# Patch worker_manager + event_engine before importing app
with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock), \
     patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock):
    from orchestrator.main import app


API_KEY_HEADER = {"X-API-KEY": "test-api-key-1234"}


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# --- Fix 1: pause -> PAUSED, stop -> STOPPED ---

@pytest.mark.asyncio
async def test_control_pause_sets_paused_status(db, client):
    # Seed a target + job
    async with get_session() as session:
        t = Target(company_name="PauseCorp", base_domain="pause.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        job = JobState(target_id=t.id, container_name="webbh-fuzzing-t1", status="RUNNING", current_phase="fuzzing")
        session.add(job)
        await session.commit()

    with patch("orchestrator.main.worker_manager.pause_worker", new_callable=AsyncMock, return_value=True):
        resp = await client.post("/api/v1/control", json={"container_name": "webbh-fuzzing-t1", "action": "pause"}, headers=API_KEY_HEADER)
    assert resp.status_code == 200

    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(JobState).where(JobState.container_name == "webbh-fuzzing-t1"))
        job = result.scalar_one()
        assert job.status == "PAUSED"


@pytest.mark.asyncio
async def test_control_stop_sets_stopped_status(db, client):
    async with get_session() as session:
        t = Target(company_name="StopCorp", base_domain="stop.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        job = JobState(target_id=t.id, container_name="webbh-fuzzing-t2", status="RUNNING", current_phase="fuzzing")
        session.add(job)
        await session.commit()

    with patch("orchestrator.main.worker_manager.stop_worker", new_callable=AsyncMock, return_value=True):
        resp = await client.post("/api/v1/control", json={"container_name": "webbh-fuzzing-t2", "action": "stop"}, headers=API_KEY_HEADER)
    assert resp.status_code == 200

    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(JobState).where(JobState.container_name == "webbh-fuzzing-t2"))
        job = result.scalar_one()
        assert job.status == "STOPPED"


# --- Fix 8: unpause action exposed ---

@pytest.mark.asyncio
async def test_control_unpause_sets_running_status(db, client):
    async with get_session() as session:
        t = Target(company_name="UnpauseCorp", base_domain="unpause.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        job = JobState(target_id=t.id, container_name="webbh-fuzzing-t3", status="PAUSED", current_phase="fuzzing")
        session.add(job)
        await session.commit()

    with patch("orchestrator.main.worker_manager.unpause_worker", new_callable=AsyncMock, return_value=True):
        resp = await client.post("/api/v1/control", json={"container_name": "webbh-fuzzing-t3", "action": "unpause"}, headers=API_KEY_HEADER)
    assert resp.status_code == 200

    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(JobState).where(JobState.container_name == "webbh-fuzzing-t3"))
        job = result.scalar_one()
        assert job.status == "RUNNING"
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py -v`
Expected: FAIL — `test_control_pause_sets_paused_status` asserts `PAUSED` but gets `QUEUED`; `test_control_unpause_sets_running_status` gets 400 "Unknown action"

**Step 3: Apply the fix in `main.py`**

In `orchestrator/main.py`, modify the `control_worker` function:

1. Add `unpause_worker` import and action entry.
2. Fix the status map.

Replace the `actions` dict and `new_status` line (~lines 193-207):

```python
actions = {
    "pause": worker_manager.pause_worker,
    "stop": worker_manager.stop_worker,
    "restart": worker_manager.restart_worker,
    "unpause": worker_manager.unpause_worker,
}
```

```python
new_status = {"pause": "PAUSED", "stop": "STOPPED", "restart": "RUNNING", "unpause": "RUNNING"}.get(body.action, "RUNNING")
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py -v`
Expected: 3 PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "fix: correct pause/stop status mappings and expose unpause action"
```

---

### Task 3: Always write config files (Fix 4/17)

**Files:**
- Modify: `orchestrator/main.py:268-288`
- Modify: `tests/test_main.py`

**Step 1: Write failing test**

Append to `tests/test_main.py`:

```python
@pytest.mark.asyncio
async def test_create_target_writes_all_config_files(db, client, tmp_path):
    """All 4 config files should be written even with empty profile."""
    with patch("orchestrator.main.SHARED_CONFIG", tmp_path), \
         patch("orchestrator.main.SHARED_RAW", tmp_path / "raw"):
        resp = await client.post("/api/v1/targets", json={
            "company_name": "ConfigCorp",
            "base_domain": "config.com",
        }, headers=API_KEY_HEADER)
    assert resp.status_code == 201
    tid = resp.json()["target_id"]
    config_dir = tmp_path / str(tid)
    assert (config_dir / "target_profile.json").exists()
    assert (config_dir / "custom_headers.json").exists()
    assert (config_dir / "rate_limits.json").exists()
    assert (config_dir / "scope.json").exists()
    # Verify empty defaults
    assert json.loads((config_dir / "custom_headers.json").read_text()) == {}
    assert json.loads((config_dir / "rate_limits.json").read_text()) == {}
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_main.py::test_create_target_writes_all_config_files -v`
Expected: FAIL — `custom_headers.json` does not exist

**Step 3: Apply the fix**

In `orchestrator/main.py`, function `_generate_tool_configs`, remove the `if` guards:

```python
def _generate_tool_configs(target_id: int, profile: dict) -> None:
    """Write tool-specific configs derived from the target profile."""
    config_dir = SHARED_CONFIG / str(target_id)
    config_dir.mkdir(parents=True, exist_ok=True)

    # Custom headers file (consumed by httpx-based workers)
    custom_headers = profile.get("custom_headers", {})
    (config_dir / "custom_headers.json").write_text(json.dumps(custom_headers, indent=2))

    # Rate-limit config
    rate_limits = profile.get("rate_limits", {})
    (config_dir / "rate_limits.json").write_text(json.dumps(rate_limits, indent=2))

    # Scope rules (consumed by ScopeManager in workers)
    scope_keys = ("in_scope_domains", "out_scope_domains", "in_scope_cidrs", "in_scope_regex")
    scope = {k: profile.get(k, []) for k in scope_keys}
    (config_dir / "scope.json").write_text(json.dumps(scope, indent=2))

    logger.info("Tool configs generated", extra={"target_id": target_id, "dir": str(config_dir)})
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_main.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "fix: always write config files with empty defaults"
```

---

### Task 4: Container name validation + auth warning (Fixes 5, 6)

**Files:**
- Modify: `orchestrator/main.py`
- Modify: `tests/test_main.py`

**Step 1: Write failing tests**

Append to `tests/test_main.py`:

```python
@pytest.mark.asyncio
async def test_control_rejects_non_webbh_container(db, client):
    resp = await client.post("/api/v1/control", json={
        "container_name": "postgres",
        "action": "stop",
    }, headers=API_KEY_HEADER)
    assert resp.status_code == 400
    assert "webbh" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_auth_rejected_without_key(db, client):
    resp = await client.get("/api/v1/status")
    assert resp.status_code == 401
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_main.py::test_control_rejects_non_webbh_container tests/test_main.py::test_auth_rejected_without_key -v`
Expected: `test_control_rejects_non_webbh_container` FAILS (gets 400 "Unknown action" or 404, not our validation message); `test_auth_rejected_without_key` may already pass if auth is wired correctly.

**Step 3: Apply the fixes**

In `orchestrator/main.py`, function `control_worker`, add the prefix guard at the top of the function body (before the `actions` dict):

```python
if not body.container_name.startswith("webbh-"):
    raise HTTPException(status_code=400, detail="Can only control webbh worker containers")
```

In the `lifespan` function, before starting background tasks, add:

```python
if not API_KEY:
    logger.warning("WEB_APP_BH_API_KEY is not set — all endpoints are unauthenticated")
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_main.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "fix: validate container names and warn on missing API key"
```

---

### Task 5: UUID for SSE consumer names (Fix 7)

**Files:**
- Modify: `orchestrator/main.py:236`

**Step 1: Apply the fix**

In `orchestrator/main.py`:

1. Add `from uuid import uuid4` to the imports section.
2. In `stream_events`, replace:
   ```python
   consumer = f"sse-{id(request)}"
   ```
   with:
   ```python
   consumer = f"sse-{uuid4().hex}"
   ```

This is a one-liner with no meaningful unit test (the old behavior was a memory-address collision risk, which is non-deterministic). The SSE endpoint is tested for overall correctness in Task 12.

**Step 2: Run existing tests to verify no regressions**

Run: `python -m pytest tests/test_main.py -v`
Expected: All PASS

**Step 3: Commit**

```bash
git add orchestrator/main.py
git commit -m "fix: use UUID for SSE consumer names to prevent collisions"
```

---

### Task 6: Web trigger checks Location.state (Fix 2)

**Files:**
- Modify: `orchestrator/event_engine.py:193-221`
- Create: `tests/test_event_engine.py`

**Step 1: Write failing test**

```python
# tests/test_event_engine.py
"""Tests for orchestrator.event_engine — triggers and heartbeat."""

import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone, timedelta

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"

import pytest_asyncio
from lib_webbh.database import (
    get_engine, get_session, Base,
    Target, Asset, Location, Parameter, CloudAsset, JobState, Alert,
)

# Patch worker_manager for all event_engine tests
@pytest.fixture(autouse=True)
def mock_wm():
    with patch("orchestrator.event_engine.worker_manager") as wm:
        wm.start_worker = AsyncMock(return_value="fake-cid")
        wm.stop_worker = AsyncMock(return_value=True)
        wm.restart_worker = AsyncMock(return_value=True)
        wm.kill_worker = AsyncMock(return_value=True)
        wm.should_queue = AsyncMock(return_value=False)
        wm.get_container_status = AsyncMock(return_value=None)
        yield wm


@pytest.fixture(autouse=True)
def mock_push():
    with patch("orchestrator.event_engine.push_task", new_callable=AsyncMock) as pt:
        yield pt


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target_with_open_port(db):
    """Target with an asset that has port 443 state='open'."""
    async with get_session() as session:
        t = Target(company_name="WebCorp", base_domain="webcorp.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="ip", asset_value="10.0.0.1", source_tool="nmap")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        loc = Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="open")
        session.add(loc)
        await session.commit()
        return t.id


@pytest_asyncio.fixture
async def seed_target_with_closed_port(db):
    """Target with an asset that has port 443 state='closed'."""
    async with get_session() as session:
        t = Target(company_name="ClosedCorp", base_domain="closed.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="ip", asset_value="10.0.0.2", source_tool="nmap")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        loc = Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="closed")
        session.add(loc)
        await session.commit()
        return t.id


# --- Fix 2: Web trigger must check Location.state ---

@pytest.mark.asyncio
async def test_web_trigger_fires_for_open_port(seed_target_with_open_port, mock_wm):
    from orchestrator.event_engine import _check_web_trigger
    await _check_web_trigger()
    mock_wm.start_worker.assert_called()


@pytest.mark.asyncio
async def test_web_trigger_ignores_closed_port(seed_target_with_closed_port, mock_wm):
    from orchestrator.event_engine import _check_web_trigger
    await _check_web_trigger()
    mock_wm.start_worker.assert_not_called()
```

**Step 2: Run tests to verify failure**

Run: `python -m pytest tests/test_event_engine.py::test_web_trigger_ignores_closed_port -v`
Expected: FAIL — closed port still triggers worker

**Step 3: Apply the fix**

In `orchestrator/event_engine.py`, function `_check_web_trigger`, add `Location.state == "open"` to the `.where()` clause:

```python
.where(
    Location.port.in_([80, 443]),
    Location.state == "open",
    Asset.target_id.notin_(select(subq_fuzz.c.target_id)),
)
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "fix: web trigger only fires for open ports"
```

---

### Task 7: Update trigger exclusions for PAUSED/STOPPED statuses

**Files:**
- Modify: `orchestrator/event_engine.py`
- Modify: `tests/test_event_engine.py`

Now that we have `PAUSED` and `STOPPED` statuses (Task 2), the trigger exclusion queries must include them so triggers don't override admin-controlled states.

**Step 1: Write failing test**

Append to `tests/test_event_engine.py`:

```python
@pytest_asyncio.fixture
async def seed_target_with_paused_web_job(db):
    """Target with open port 443 AND a PAUSED fuzzing job."""
    async with get_session() as session:
        t = Target(company_name="PausedWeb", base_domain="pausedweb.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="ip", asset_value="10.0.0.3", source_tool="nmap")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        loc = Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="open")
        session.add(loc)
        await session.commit()
        job = JobState(target_id=t.id, container_name="webbh-fuzzing-t" + str(t.id), status="PAUSED", current_phase="fuzzing")
        session.add(job)
        await session.commit()
        return t.id


@pytest.mark.asyncio
async def test_web_trigger_does_not_override_paused_job(seed_target_with_paused_web_job, mock_wm):
    from orchestrator.event_engine import _check_web_trigger
    await _check_web_trigger()
    mock_wm.start_worker.assert_not_called()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_event_engine.py::test_web_trigger_does_not_override_paused_job -v`
Expected: FAIL — `PAUSED` not in the exclusion list, so a new worker is triggered

**Step 3: Apply the fix**

In all three trigger functions in `orchestrator/event_engine.py`, update the status exclusion lists from `["RUNNING", "QUEUED"]` to `["RUNNING", "QUEUED", "PAUSED", "STOPPED"]`:

1. `_check_cloud_trigger` — line with `JobState.status.in_(["RUNNING", "QUEUED"])`
2. `_check_web_trigger` — line with `JobState.status.in_(["RUNNING", "QUEUED"])`
3. `_check_api_trigger` — line with `JobState.status.in_(["RUNNING", "QUEUED"])`

Extract the list into a module-level constant for DRY:

```python
# Near the top of event_engine.py, after WORKER_IMAGES
ACTIVE_STATUSES = ["RUNNING", "QUEUED", "PAUSED", "STOPPED"]
```

Then replace all three occurrences of `["RUNNING", "QUEUED"]` with `ACTIVE_STATUSES`.

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "fix: triggers respect PAUSED and STOPPED statuses"
```

---

### Task 8: Cloud trigger ignores stale assets (Fix 9)

**Files:**
- Modify: `orchestrator/event_engine.py:170-190`
- Modify: `tests/test_event_engine.py`

**Step 1: Write failing test**

Append to `tests/test_event_engine.py`:

```python
@pytest_asyncio.fixture
async def seed_target_with_stale_cloud_asset(db):
    """Target with a cloud_asset created BEFORE the last completed cloud job."""
    async with get_session() as session:
        t = Target(company_name="StaleCorp", base_domain="stale.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)

        # Cloud asset created first
        ca = CloudAsset(target_id=t.id, provider="aws", asset_type="s3", url="s3://stale-bucket")
        session.add(ca)
        await session.commit()

        # Then a cloud job ran and completed AFTER the asset was created
        job = JobState(
            target_id=t.id,
            container_name=f"webbh-cloud_testing-t{t.id}",
            status="COMPLETED",
            current_phase="cloud_enum",
            last_seen=datetime.now(timezone.utc),
        )
        session.add(job)
        await session.commit()
        return t.id


@pytest_asyncio.fixture
async def seed_target_with_fresh_cloud_asset(db):
    """Target with a cloud_asset created AFTER the last completed cloud job."""
    async with get_session() as session:
        t = Target(company_name="FreshCorp", base_domain="fresh.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)

        # Old completed job
        job = JobState(
            target_id=t.id,
            container_name=f"webbh-cloud_testing-t{t.id}",
            status="COMPLETED",
            current_phase="cloud_enum",
            last_seen=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        session.add(job)
        await session.commit()

        # New cloud asset discovered after the job finished
        ca = CloudAsset(target_id=t.id, provider="aws", asset_type="s3", url="s3://fresh-bucket")
        session.add(ca)
        await session.commit()
        return t.id


@pytest.mark.asyncio
async def test_cloud_trigger_ignores_stale_assets(seed_target_with_stale_cloud_asset, mock_wm):
    from orchestrator.event_engine import _check_cloud_trigger
    await _check_cloud_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_cloud_trigger_fires_for_fresh_assets(seed_target_with_fresh_cloud_asset, mock_wm):
    from orchestrator.event_engine import _check_cloud_trigger
    await _check_cloud_trigger()
    mock_wm.start_worker.assert_called()
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_event_engine.py::test_cloud_trigger_ignores_stale_assets -v`
Expected: FAIL — stale asset still triggers

**Step 3: Apply the fix**

Replace `_check_cloud_trigger` in `orchestrator/event_engine.py`:

```python
async def _check_cloud_trigger() -> None:
    """If new cloud_assets appeared since the last completed cloud job, trigger cloud worker."""
    async with get_session() as session:
        # Subquery: targets with an active cloud job (skip them)
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-cloud_testing-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        # Subquery: latest completed cloud job's last_seen per target
        from sqlalchemy import func as sa_func
        done_sub = (
            select(
                JobState.target_id,
                sa_func.max(JobState.last_seen).label("done_at"),
            )
            .where(
                JobState.container_name.like("webbh-cloud_testing-%"),
                JobState.status.in_(["COMPLETED", "STOPPED", "FAILED"]),
            )
            .group_by(JobState.target_id)
        ).subquery()

        # Find targets with cloud_assets newer than the last completed job
        stmt = (
            select(CloudAsset.target_id)
            .outerjoin(done_sub, done_sub.c.target_id == CloudAsset.target_id)
            .where(
                CloudAsset.target_id.notin_(select(active_sub.c.target_id)),
                sa_func.coalesce(CloudAsset.created_at, sa_func.now()) > sa_func.coalesce(done_sub.c.done_at, datetime(1970, 1, 1, tzinfo=timezone.utc)),
            )
            .group_by(CloudAsset.target_id)
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Cloud trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "cloud_testing", "cloud_enum")
```

Note: The `from sqlalchemy import func as sa_func` can be moved to the module-level imports (there's already `from sqlalchemy import func` at the top — just use `func` directly). The above shows the logic clearly.

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "fix: cloud trigger only fires for assets newer than last completed job"
```

---

### Task 9: Heartbeat grace period (Fix 3)

**Files:**
- Modify: `orchestrator/event_engine.py:295-355`
- Modify: `tests/test_event_engine.py`

**Step 1: Write failing test**

Append to `tests/test_event_engine.py`:

```python
from orchestrator.worker_manager import ContainerInfo


@pytest_asyncio.fixture
async def seed_running_job_recent(db):
    """A RUNNING job with recent last_seen (within zombie timeout)."""
    async with get_session() as session:
        t = Target(company_name="GraceCorp", base_domain="grace.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        job = JobState(
            target_id=t.id,
            container_name="webbh-fuzzing-tgrace",
            status="RUNNING",
            current_phase="fuzzing",
            last_seen=datetime.now(timezone.utc) - timedelta(seconds=30),
        )
        session.add(job)
        await session.commit()
        return t.id


@pytest.mark.asyncio
async def test_heartbeat_grace_period_for_vanished_container(seed_running_job_recent, mock_wm):
    """Container gone but last_seen is recent — should NOT mark FAILED."""
    mock_wm.get_container_status = AsyncMock(return_value=None)  # container gone

    from orchestrator.event_engine import _heartbeat_cycle
    await _heartbeat_cycle()

    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(JobState).where(JobState.container_name == "webbh-fuzzing-tgrace"))
        job = result.scalar_one()
        # Should still be RUNNING (grace period), NOT FAILED
        assert job.status == "RUNNING"
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_event_engine.py::test_heartbeat_grace_period_for_vanished_container -v`
Expected: FAIL — job gets marked FAILED immediately

**Step 3: Apply the fix**

In `orchestrator/event_engine.py`, function `_heartbeat_cycle`, replace the `else` branch (lines ~336-345) that handles "container gone but within timeout":

```python
# Current (WRONG):
else:
    # Container gone but within timeout — mark FAILED
    async with get_session() as session:
        stmt = (update(JobState).where(JobState.id == job.id).values(status="FAILED", last_seen=now))
        await session.execute(stmt)
        await session.commit()

# Replace with:
else:
    # Container gone but within timeout — grace period for restart policy
    logger.info(
        "Container missing but within grace period",
        extra={"container": job.container_name, "last_seen": str(job.last_seen)},
    )
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "fix: heartbeat grace period for vanished containers within zombie timeout"
```

---

### Task 10: Zombie cleanup restarts worker with retry limit (Fix 10)

**Files:**
- Modify: `orchestrator/event_engine.py`
- Modify: `tests/test_event_engine.py`

**Step 1: Write failing tests**

Append to `tests/test_event_engine.py`:

```python
@pytest_asyncio.fixture
async def seed_zombie_job(db):
    """A RUNNING job with last_seen beyond zombie timeout, no container."""
    async with get_session() as session:
        t = Target(company_name="ZombieCorp", base_domain="zombie.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        job = JobState(
            target_id=t.id,
            container_name="webbh-fuzzing-tzombie",
            status="RUNNING",
            current_phase="fuzzing",
            last_seen=datetime.now(timezone.utc) - timedelta(seconds=700),
        )
        session.add(job)
        await session.commit()
        return t.id


@pytest.mark.asyncio
async def test_zombie_triggers_restart(seed_zombie_job, mock_wm):
    """Zombie job should be killed, marked FAILED, and restarted."""
    mock_wm.get_container_status = AsyncMock(return_value=None)

    from orchestrator.event_engine import _heartbeat_cycle
    await _heartbeat_cycle()

    # Worker should have been restarted
    mock_wm.start_worker.assert_called()

    # Alert should exist
    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(Alert).where(Alert.alert_type == "ZOMBIE_RESTART"))
        alert = result.scalar_one()
        assert "webbh-fuzzing-tzombie" in alert.message


@pytest_asyncio.fixture
async def seed_zombie_job_exceeded_retries(db):
    """A zombie job that has already been restarted ZOMBIE_MAX_RETRIES times."""
    async with get_session() as session:
        t = Target(company_name="MaxRetryCorp", base_domain="maxretry.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        job = JobState(
            target_id=t.id,
            container_name="webbh-fuzzing-tmaxretry",
            status="RUNNING",
            current_phase="fuzzing",
            last_seen=datetime.now(timezone.utc) - timedelta(seconds=700),
        )
        session.add(job)
        await session.commit()
        # Create 3 prior ZOMBIE_RESTART alerts (at max retries)
        for i in range(3):
            alert = Alert(
                target_id=t.id,
                alert_type="ZOMBIE_RESTART",
                message=f"Container webbh-fuzzing-tmaxretry zombie restart #{i+1}",
            )
            session.add(alert)
        await session.commit()
        return t.id


@pytest.mark.asyncio
async def test_zombie_does_not_restart_after_max_retries(seed_zombie_job_exceeded_retries, mock_wm):
    """After ZOMBIE_MAX_RETRIES, zombie should be killed but NOT restarted."""
    mock_wm.get_container_status = AsyncMock(return_value=None)

    with patch("orchestrator.event_engine.ZOMBIE_MAX_RETRIES", 3):
        from orchestrator.event_engine import _heartbeat_cycle
        await _heartbeat_cycle()

    # Worker should NOT have been restarted
    mock_wm.start_worker.assert_not_called()

    # Should have a CRITICAL_ALERT
    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(Alert).where(Alert.alert_type == "CRITICAL_ALERT"))
        alerts = result.scalars().all()
        assert len(alerts) >= 1
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_event_engine.py::test_zombie_triggers_restart tests/test_event_engine.py::test_zombie_does_not_restart_after_max_retries -v`
Expected: FAIL — no restart happens, no CRITICAL_ALERT

**Step 3: Apply the fix**

In `orchestrator/event_engine.py`:

1. Add config constant near the top:
   ```python
   ZOMBIE_MAX_RETRIES = int(os.environ.get("ZOMBIE_MAX_RETRIES", "3"))
   ```

2. In `_heartbeat_cycle`, replace the zombie handling block (the `if job.last_seen and job.last_seen < cutoff:` branch). After killing and marking FAILED and creating the ZOMBIE_RESTART alert, add restart logic:

```python
if job.last_seen and job.last_seen < cutoff:
    logger.warning(
        "ZOMBIE_RESTART — killing unresponsive job",
        extra={"container": job.container_name, "last_seen": str(job.last_seen)},
    )
    await worker_manager.kill_worker(job.container_name)

    async with get_session() as session:
        stmt = (
            update(JobState)
            .where(JobState.id == job.id)
            .values(status="FAILED", last_seen=now)
        )
        await session.execute(stmt)
        await session.commit()

    # Check retry count before restarting
    async with get_session() as session:
        retry_stmt = (
            select(func.count(Alert.id))
            .where(
                Alert.target_id == job.target_id,
                Alert.alert_type == "ZOMBIE_RESTART",
                Alert.message.like(f"%{job.container_name}%"),
            )
        )
        result = await session.execute(retry_stmt)
        retry_count = result.scalar() or 0

    if retry_count >= ZOMBIE_MAX_RETRIES:
        # Permanently failed — emit critical alert
        async with get_session() as session:
            alert = Alert(
                target_id=job.target_id,
                alert_type="CRITICAL_ALERT",
                message=f"Container {job.container_name} exceeded {ZOMBIE_MAX_RETRIES} zombie restarts. Permanently failed.",
            )
            session.add(alert)
            await session.commit()
        await _emit_event(job.target_id, "CRITICAL_ALERT", {
            "container": job.container_name,
            "message": f"Exceeded {ZOMBIE_MAX_RETRIES} zombie restarts",
        })
    else:
        # Create alert and restart
        async with get_session() as session:
            alert = Alert(
                target_id=job.target_id,
                alert_type="ZOMBIE_RESTART",
                message=f"Container {job.container_name} was unresponsive for >{ZOMBIE_TIMEOUT}s and was killed. Restarting (attempt {retry_count + 1}/{ZOMBIE_MAX_RETRIES}).",
            )
            session.add(alert)
            await session.commit()

        # Restart the worker
        parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
        worker_key = parts[0] if parts else None
        if worker_key and worker_key in WORKER_IMAGES:
            await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "feat: zombie cleanup restarts worker with retry limit"
```

---

### Task 11: Pass API key to worker env (Fix 11)

**Files:**
- Modify: `orchestrator/event_engine.py:107-118`
- Modify: `tests/test_event_engine.py`

**Step 1: Write failing test**

Append to `tests/test_event_engine.py`:

```python
def test_worker_env_includes_api_key():
    with patch.dict(os.environ, {"WEB_APP_BH_API_KEY": "secret-key-123"}):
        from orchestrator.event_engine import _worker_env
        env = _worker_env(target_id=1)
        assert env["WEB_APP_BH_API_KEY"] == "secret-key-123"
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_event_engine.py::test_worker_env_includes_api_key -v`
Expected: FAIL — KeyError

**Step 3: Apply the fix**

In `orchestrator/event_engine.py`, function `_worker_env`, add to the returned dict:

```python
"WEB_APP_BH_API_KEY": os.environ.get("WEB_APP_BH_API_KEY", ""),
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "fix: pass API key to worker environment"
```

---

### Task 12: Non-blocking CPU check (Fix 14)

**Files:**
- Modify: `orchestrator/worker_manager.py:271`
- Modify: `tests/test_worker_manager.py`

**Step 1: Write test that verifies interval=None is used**

Append to `tests/test_worker_manager.py`:

```python
@pytest.mark.asyncio
async def test_check_resources_uses_non_blocking_cpu():
    """cpu_percent should be called with interval=None (non-blocking)."""
    with patch("orchestrator.worker_manager.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 50.0
        mock_mem = MagicMock()
        mock_mem.percent = 60.0
        mock_psutil.virtual_memory.return_value = mock_mem
        await check_resources()
        mock_psutil.cpu_percent.assert_called_once_with(interval=None)
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_worker_manager.py::test_check_resources_uses_non_blocking_cpu -v`
Expected: FAIL — called with `interval=1`

**Step 3: Apply the fix**

In `orchestrator/worker_manager.py:271`, change:

```python
cpu = psutil.cpu_percent(interval=1)
```

to:

```python
cpu = psutil.cpu_percent(interval=None)
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_worker_manager.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/worker_manager.py tests/test_worker_manager.py
git commit -m "fix: use non-blocking cpu_percent to avoid 1s executor stall"
```

---

### Task 13: SSE pending message cleanup (Fix 13)

**Files:**
- Modify: `orchestrator/main.py:243-261`
- Modify: `tests/test_main.py`

**Step 1: Write test**

Append to `tests/test_main.py`:

```python
@pytest.mark.asyncio
async def test_sse_generator_cleans_up_on_disconnect():
    """The SSE generator should release pending messages on disconnect."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from uuid import uuid4

    mock_redis = AsyncMock()
    mock_redis.xgroup_create = AsyncMock()
    mock_redis.xreadgroup = AsyncMock(return_value=[])
    mock_redis.xack = AsyncMock()
    mock_redis.xautoclaim = AsyncMock()

    mock_request = AsyncMock()
    # Immediately disconnected
    mock_request.is_disconnected = AsyncMock(return_value=True)

    with patch("orchestrator.main.get_redis", return_value=mock_redis), \
         patch("orchestrator.main.uuid4") as mock_uuid:
        mock_uuid.return_value = MagicMock(hex="abc123")
        from orchestrator.main import stream_events
        response = await stream_events(target_id=1, request=mock_request)

        # Consume the generator to trigger the finally block
        gen = response.body_iterator
        async for _ in gen:
            pass

    # xautoclaim should have been called during cleanup
    mock_redis.xautoclaim.assert_called_once()
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_main.py::test_sse_generator_cleans_up_on_disconnect -v`
Expected: FAIL — no `xautoclaim` call

**Step 3: Apply the fix**

In `orchestrator/main.py`, modify the `_generate()` inner function in `stream_events` to wrap the loop in try/finally:

```python
async def _generate():
    last_id = ">"
    try:
        while True:
            if await request.is_disconnected():
                break
            messages = await redis.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={queue: last_id},
                count=10,
                block=2000,
            )
            for _, entries in messages:
                for msg_id, data in entries:
                    payload = json.loads(data.get("payload", "{}"))
                    event_type = payload.get("event", "message")
                    yield {"event": event_type, "data": json.dumps(payload)}
                    await redis.xack(queue, group, msg_id)
    finally:
        # Release any claimed-but-unacked messages
        try:
            await redis.xautoclaim(queue, group, consumer, min_idle_time=0)
        except Exception:
            pass
```

Also add `from lib_webbh.messaging import get_redis` to the module-level imports instead of the inline import inside the function, since it's also used by the `uuid4` import now at the top.

**Step 4: Run tests**

Run: `python -m pytest tests/test_main.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "fix: SSE generator cleans up pending messages on disconnect"
```

---

### Task 14: Batch heartbeat sessions (Fix 12)

**Files:**
- Modify: `orchestrator/event_engine.py:295-355`
- Modify: `tests/test_event_engine.py`

This is a refactor of `_heartbeat_cycle` to use fewer DB sessions. The existing tests from Tasks 9 and 10 serve as regression tests. Add one test to verify batching behavior.

**Step 1: Write test**

Append to `tests/test_event_engine.py`:

```python
@pytest_asyncio.fixture
async def seed_multiple_running_jobs(db):
    """Three RUNNING jobs: one healthy container, one grace period, one zombie."""
    now = datetime.now(timezone.utc)
    async with get_session() as session:
        t = Target(company_name="BatchCorp", base_domain="batch.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)

        # Job 1: healthy (container will be found running)
        j1 = JobState(target_id=t.id, container_name="webbh-fuzzing-tbatch1", status="RUNNING", current_phase="fuzzing", last_seen=now - timedelta(seconds=10))
        # Job 2: grace period (container gone, recent last_seen)
        j2 = JobState(target_id=t.id, container_name="webbh-webapp_testing-tbatch2", status="RUNNING", current_phase="webapp_testing", last_seen=now - timedelta(seconds=30))
        # Job 3: zombie (container gone, old last_seen)
        j3 = JobState(target_id=t.id, container_name="webbh-api_testing-tbatch3", status="RUNNING", current_phase="api_testing", last_seen=now - timedelta(seconds=700))
        session.add_all([j1, j2, j3])
        await session.commit()
        return t.id


@pytest.mark.asyncio
async def test_heartbeat_handles_mixed_job_states(seed_multiple_running_jobs, mock_wm):
    """Heartbeat correctly classifies healthy, grace, and zombie jobs."""
    healthy_info = ContainerInfo(name="webbh-fuzzing-tbatch1", status="running", image="test:latest")

    async def _status(name):
        if name == "webbh-fuzzing-tbatch1":
            return healthy_info
        return None  # gone

    mock_wm.get_container_status = AsyncMock(side_effect=_status)

    from orchestrator.event_engine import _heartbeat_cycle
    await _heartbeat_cycle()

    async with get_session() as session:
        from sqlalchemy import select
        jobs = {j.container_name: j for j in (await session.execute(select(JobState))).scalars().all()}

    # Healthy: still RUNNING, last_seen updated
    assert jobs["webbh-fuzzing-tbatch1"].status == "RUNNING"
    # Grace: still RUNNING (not marked FAILED)
    assert jobs["webbh-webapp_testing-tbatch2"].status == "RUNNING"
    # Zombie: marked FAILED
    assert jobs["webbh-api_testing-tbatch3"].status == "FAILED"
```

**Step 2: Run to verify it passes or fails**

Run: `python -m pytest tests/test_event_engine.py::test_heartbeat_handles_mixed_job_states -v`

This test may already pass after Tasks 9/10. If so, proceed with the refactor and re-verify.

**Step 3: Refactor `_heartbeat_cycle`**

Replace `_heartbeat_cycle` in `orchestrator/event_engine.py` with the batched version:

```python
async def _heartbeat_cycle() -> None:
    """Single heartbeat iteration — batched DB access."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=ZOMBIE_TIMEOUT)

    # --- Read phase ---
    async with get_session() as session:
        stmt = select(JobState).where(JobState.status == "RUNNING")
        result = await session.execute(stmt)
        running_jobs = result.scalars().all()

    if not running_jobs:
        # Promote queued jobs if resources allow
        await _promote_queued_jobs()
        return

    # Gather container statuses concurrently
    import asyncio as _asyncio
    statuses = await _asyncio.gather(
        *(worker_manager.get_container_status(j.container_name) for j in running_jobs)
    )

    # Classify jobs
    healthy_ids: list[int] = []
    grace_jobs: list[JobState] = []
    zombie_jobs: list[JobState] = []

    for job, info in zip(running_jobs, statuses):
        if info is not None and info.status == "running":
            healthy_ids.append(job.id)
        elif job.last_seen and job.last_seen < cutoff:
            zombie_jobs.append(job)
        else:
            grace_jobs.append(job)

    # --- Write phase ---
    async with get_session() as session:
        # Bulk update last_seen for healthy jobs
        if healthy_ids:
            stmt = (
                update(JobState)
                .where(JobState.id.in_(healthy_ids))
                .values(last_seen=now)
            )
            await session.execute(stmt)

        await session.commit()

    # Log grace-period jobs
    for job in grace_jobs:
        logger.info(
            "Container missing but within grace period",
            extra={"container": job.container_name, "last_seen": str(job.last_seen)},
        )

    # Handle zombies (needs individual processing for alerts + restarts)
    for job in zombie_jobs:
        await _handle_zombie(job, now)

    # Promote queued jobs
    await _promote_queued_jobs()
```

Extract `_promote_queued_jobs` from the old heartbeat:

```python
async def _promote_queued_jobs() -> None:
    """Promote QUEUED jobs if resources are available."""
    if await worker_manager.should_queue():
        return

    async with get_session() as session:
        stmt = select(JobState).where(JobState.status == "QUEUED").order_by(JobState.created_at)
        result = await session.execute(stmt)
        queued = result.scalars().all()

    for job in queued:
        parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
        worker_key = parts[0] if parts else None
        if worker_key and worker_key in WORKER_IMAGES:
            await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)
            if await worker_manager.should_queue():
                break
```

Extract `_handle_zombie` from the old zombie block (incorporating the restart logic from Task 10):

```python
async def _handle_zombie(job: JobState, now: datetime) -> None:
    """Kill a zombie job, create alert, and restart if within retry limit."""
    logger.warning(
        "ZOMBIE_RESTART — killing unresponsive job",
        extra={"container": job.container_name, "last_seen": str(job.last_seen)},
    )
    await worker_manager.kill_worker(job.container_name)

    async with get_session() as session:
        stmt = update(JobState).where(JobState.id == job.id).values(status="FAILED", last_seen=now)
        await session.execute(stmt)

        # Count prior zombie restarts
        retry_stmt = (
            select(func.count(Alert.id))
            .where(
                Alert.target_id == job.target_id,
                Alert.alert_type == "ZOMBIE_RESTART",
                Alert.message.like(f"%{job.container_name}%"),
            )
        )
        result = await session.execute(retry_stmt)
        retry_count = result.scalar() or 0

        if retry_count >= ZOMBIE_MAX_RETRIES:
            alert = Alert(
                target_id=job.target_id,
                alert_type="CRITICAL_ALERT",
                message=f"Container {job.container_name} exceeded {ZOMBIE_MAX_RETRIES} zombie restarts. Permanently failed.",
            )
            session.add(alert)
        else:
            alert = Alert(
                target_id=job.target_id,
                alert_type="ZOMBIE_RESTART",
                message=f"Container {job.container_name} was unresponsive for >{ZOMBIE_TIMEOUT}s. Restarting (attempt {retry_count + 1}/{ZOMBIE_MAX_RETRIES}).",
            )
            session.add(alert)

        await session.commit()

    if retry_count >= ZOMBIE_MAX_RETRIES:
        await _emit_event(job.target_id, "CRITICAL_ALERT", {
            "container": job.container_name,
            "message": f"Exceeded {ZOMBIE_MAX_RETRIES} zombie restarts",
        })
    else:
        parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
        worker_key = parts[0] if parts else None
        if worker_key and worker_key in WORKER_IMAGES:
            await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)
```

**Step 4: Run all event_engine tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "refactor: batch heartbeat DB sessions and extract helper functions"
```

---

### Task 15: Redis background listener (Fix 10/P3)

**Files:**
- Modify: `orchestrator/event_engine.py`
- Modify: `orchestrator/main.py` (lifespan)
- Modify: `tests/test_event_engine.py`

**Step 1: Write failing test**

Append to `tests/test_event_engine.py`:

```python
@pytest.mark.asyncio
async def test_redis_listener_callback_dispatches_web_location(mock_push):
    """A recon_queue message with asset_type=location and port 443 should push to fuzzing_queue."""
    from orchestrator.event_engine import _dispatch_recon_event

    msg_data = {
        "asset_type": "location",
        "asset_id": 42,
        "target_id": 1,
        "port": 443,
        "state": "open",
    }

    await _dispatch_recon_event("msg-001", msg_data)

    # Should push to both fuzzing_queue and webapp_queue
    calls = mock_push.call_args_list
    queues_pushed = [c[0][0] for c in calls]
    assert "fuzzing_queue" in queues_pushed
    assert "webapp_queue" in queues_pushed


@pytest.mark.asyncio
async def test_redis_listener_callback_dispatches_cloud_asset(mock_push):
    from orchestrator.event_engine import _dispatch_recon_event

    msg_data = {
        "asset_type": "cloud_asset",
        "asset_id": 99,
        "target_id": 2,
    }

    await _dispatch_recon_event("msg-002", msg_data)

    calls = mock_push.call_args_list
    queues_pushed = [c[0][0] for c in calls]
    assert "cloud_queue" in queues_pushed


@pytest.mark.asyncio
async def test_redis_listener_callback_dispatches_param(mock_push):
    from orchestrator.event_engine import _dispatch_recon_event

    msg_data = {
        "asset_type": "param",
        "asset_id": 55,
        "target_id": 3,
    }

    await _dispatch_recon_event("msg-003", msg_data)

    calls = mock_push.call_args_list
    queues_pushed = [c[0][0] for c in calls]
    assert "api_queue" in queues_pushed


@pytest.mark.asyncio
async def test_redis_listener_callback_ignores_closed_port(mock_push):
    from orchestrator.event_engine import _dispatch_recon_event

    msg_data = {
        "asset_type": "location",
        "asset_id": 42,
        "target_id": 1,
        "port": 443,
        "state": "closed",
    }

    await _dispatch_recon_event("msg-004", msg_data)
    mock_push.assert_not_called()
```

**Step 2: Run to verify failure**

Run: `python -m pytest tests/test_event_engine.py::test_redis_listener_callback_dispatches_web_location -v`
Expected: FAIL — `_dispatch_recon_event` does not exist

**Step 3: Implement the Redis listener**

In `orchestrator/event_engine.py`, add the callback and listener:

```python
# ---------------------------------------------------------------------------
# Redis background listener — real-time reactive path
# ---------------------------------------------------------------------------
async def _dispatch_recon_event(msg_id: str, data: dict) -> None:
    """Fan out a recon_queue message to the appropriate work queue."""
    asset_type = data.get("asset_type")
    target_id = data.get("target_id")

    if asset_type == "location":
        port = data.get("port")
        state = data.get("state")
        if port in (80, 443) and state == "open":
            await push_task("fuzzing_queue", data)
            await push_task("webapp_queue", data)
            logger.info("Dispatched web location to fuzzing + webapp queues",
                        extra={"target_id": target_id, "asset_id": data.get("asset_id")})

    elif asset_type == "cloud_asset":
        await push_task("cloud_queue", data)
        logger.info("Dispatched cloud asset to cloud_queue",
                    extra={"target_id": target_id})

    elif asset_type == "param":
        await push_task("api_queue", data)
        logger.info("Dispatched param to api_queue",
                    extra={"target_id": target_id})


async def run_redis_listener() -> None:
    """Listen on recon_queue and fan out to work queues.

    Complements the DB poll loop — this provides sub-second reactivity.
    """
    from lib_webbh import listen_queue

    logger.info("Redis listener started on recon_queue")
    await listen_queue(
        queue="recon_queue",
        group="orchestrator",
        consumer="event-engine",
        callback=_dispatch_recon_event,
    )
```

In `orchestrator/main.py`, add the Redis listener to the `lifespan`:

After the existing two `asyncio.create_task` calls:

```python
redis_task = asyncio.create_task(event_engine.run_redis_listener(), name="redis-listener")
```

And in the shutdown block, add `redis_task` to the cancel list:

```python
redis_task.cancel()
for task in (engine_task, heartbeat_task, redis_task):
```

**Step 4: Run tests**

Run: `python -m pytest tests/test_event_engine.py -v`
Expected: All PASS

**Step 5: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All PASS (no regressions in lib_webbh tests)

**Step 6: Commit**

```bash
git add orchestrator/event_engine.py orchestrator/main.py tests/test_event_engine.py
git commit -m "feat: add Redis background listener for real-time recon event dispatch"
```

---

### Task 16: Final verification

**Step 1: Run the full test suite**

Run: `python -m pytest tests/ -v --tb=short`
Expected: All PASS

**Step 2: Verify all files are committed**

Run: `git status`
Expected: Clean working tree

**Step 3: Review the diff since the start**

Run: `git log --oneline -20`

Expected commits (oldest to newest):
1. `test: add orchestrator test infrastructure and worker_manager tests`
2. `fix: correct pause/stop status mappings and expose unpause action`
3. `fix: always write config files with empty defaults`
4. `fix: validate container names and warn on missing API key`
5. `fix: use UUID for SSE consumer names to prevent collisions`
6. `fix: web trigger only fires for open ports`
7. `fix: triggers respect PAUSED and STOPPED statuses`
8. `fix: cloud trigger only fires for assets newer than last completed job`
9. `fix: heartbeat grace period for vanished containers within zombie timeout`
10. `feat: zombie cleanup restarts worker with retry limit`
11. `fix: pass API key to worker environment`
12. `fix: use non-blocking cpu_percent to avoid 1s executor stall`
13. `fix: SSE generator cleans up pending messages on disconnect`
14. `refactor: batch heartbeat DB sessions and extract helper functions`
15. `feat: add Redis background listener for real-time recon event dispatch`
