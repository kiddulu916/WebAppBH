# Kill Switch, Rerun & Clean Slate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a global kill switch, target rerun with playbook selection, clean slate reset, and single-target enforcement to the WebAppBH framework.

**Architecture:** Three new orchestrator endpoints (`/kill`, `/rerun`, `/targets/{id}/clean-slate`) backed by existing `worker_manager.kill_worker()`. Dashboard gets a kill button in TopBar, rerun popover on C2 page, and clean slate in SettingsDrawer. Three new SSE events (`KILL_ALL`, `RERUN_STARTED`, `CLEAN_SLATE`) for real-time UI feedback. Single-target enforcement gates `POST /targets` with a 409 when another target has active jobs.

**Tech Stack:** Python (FastAPI, SQLAlchemy async), TypeScript (Next.js 16, React 19, Zustand, Tailwind v4, Lucide icons)

**Design doc:** `docs/plans/design/2026-03-22-kill-switch-rerun-design.md`

---

## Task 1: Database — Add `last_playbook` column to Target and `KILLED` status

**Files:**
- Modify: `shared/lib_webbh/database.py:131-156` (Target model)
- Modify: `dashboard/src/types/schema.ts:16` (JobStatus type)
- Modify: `dashboard/src/types/schema.ts:47-52` (Target interface)
- Test: `tests/test_kill_rerun.py` (new file)

**Step 1: Write the failing test**

Create `tests/test_kill_rerun.py`:

```python
# tests/test_kill_rerun.py
"""Tests for kill switch, rerun, and clean slate API endpoints."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import (
    Base, Target, Asset, JobState, Vulnerability, Parameter,
    Location, Observation, Identity, CloudAsset, AssetSnapshot,
    Alert, ApiSchema, ScopeViolation, BountySubmission,
    get_engine, get_session,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(
            company_name="KillTest",
            base_domain="killtest.com",
            target_profile={},
            last_playbook="wide_recon",
        )
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.mark.anyio
async def test_target_last_playbook_column(seed_target):
    """Target model has a last_playbook column."""
    async with get_session() as session:
        from sqlalchemy import select
        t = (await session.execute(select(Target).where(Target.id == seed_target))).scalar_one()
        assert t.last_playbook == "wide_recon"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_kill_rerun.py::test_target_last_playbook_column -v`
Expected: FAIL — `Target` has no `last_playbook` attribute.

**Step 3: Add `last_playbook` column to Target model**

In `shared/lib_webbh/database.py`, add after line 142 (`target_profile`):

```python
    last_playbook: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_kill_rerun.py::test_target_last_playbook_column -v`
Expected: PASS

**Step 5: Update TypeScript types**

In `dashboard/src/types/schema.ts`, update `JobStatus` (line 16):

```typescript
export type JobStatus = "QUEUED" | "RUNNING" | "PAUSED" | "STOPPED" | "COMPLETED" | "FAILED" | "KILLED";
```

Update `Target` interface (line 47-52) — add `last_playbook`:

```typescript
export interface Target extends Timestamps {
  id: number;
  company_name: string;
  base_domain: string;
  target_profile: TargetProfile | null;
  last_playbook: string | null;
}
```

**Step 6: Commit**

```bash
git add shared/lib_webbh/database.py dashboard/src/types/schema.ts tests/test_kill_rerun.py
git commit -m "feat: add last_playbook column and KILLED job status"
```

---

## Task 2: Backend — Kill endpoint

**Files:**
- Modify: `orchestrator/main.py` (add endpoint after control endpoint ~line 412)
- Test: `tests/test_kill_rerun.py` (add tests)

**Step 1: Write the failing test**

Append to `tests/test_kill_rerun.py`:

```python
@pytest_asyncio.fixture
async def seed_running_jobs(seed_target):
    """Insert 2 RUNNING + 1 QUEUED job for the seed target."""
    tid = seed_target
    async with get_session() as session:
        for name, status in [
            (f"webbh-recon-t{tid}", "RUNNING"),
            (f"webbh-fuzzing-t{tid}", "RUNNING"),
            (f"webbh-cloud_testing-t{tid}", "QUEUED"),
        ]:
            session.add(JobState(
                target_id=tid, container_name=name,
                current_phase="passive_discovery", status=status,
            ))
        await session.commit()
    return tid


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_redis_listener", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_autoscaler", new_callable=AsyncMock):
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(
            transport=transport, base_url="http://test",
            headers={"X-API-KEY": "test-api-key-1234"},
        )


@pytest.mark.anyio
async def test_kill_all_workers(client, seed_running_jobs):
    """POST /api/v1/kill should SIGKILL all active containers and mark jobs KILLED."""
    tid = seed_running_jobs
    with patch("orchestrator.worker_manager.kill_worker", new_callable=AsyncMock, return_value=True) as mock_kill, \
         patch("lib_webbh.messaging.push_task", new_callable=AsyncMock):
        resp = await client.post("/api/v1/kill")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["killed_count"] == 3
    assert len(body["containers"]) == 3
    # kill_worker called only for RUNNING/PAUSED (not QUEUED)
    assert mock_kill.call_count == 2

    # Verify all jobs are now KILLED
    async with get_session() as session:
        from sqlalchemy import select
        jobs = (await session.execute(
            select(JobState).where(JobState.target_id == tid)
        )).scalars().all()
        for j in jobs:
            assert j.status == "KILLED"


@pytest.mark.anyio
async def test_kill_idempotent(client, db):
    """POST /api/v1/kill with no active jobs returns killed_count=0."""
    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock):
        resp = await client.post("/api/v1/kill")
    assert resp.status_code == 200
    assert resp.json()["killed_count"] == 0
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_kill_rerun.py::test_kill_all_workers tests/test_kill_rerun.py::test_kill_idempotent -v`
Expected: FAIL — no route `/api/v1/kill`.

**Step 3: Implement the kill endpoint**

In `orchestrator/main.py`, add after the control endpoint (after line 412):

```python
# ---------------------------------------------------------------------------
# POST /api/v1/kill — hard-kill all active workers
# ---------------------------------------------------------------------------
@app.post("/api/v1/kill")
async def kill_all():
    """SIGKILL all RUNNING/PAUSED containers and mark all active jobs as KILLED."""
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]
    killable_statuses = ["RUNNING", "PAUSED"]  # containers to actually SIGKILL

    async with get_session() as session:
        stmt = select(JobState).where(JobState.status.in_(active_statuses))
        result = await session.execute(stmt)
        jobs = result.scalars().all()

        if not jobs:
            return {"success": True, "killed_count": 0, "containers": []}

        target_id = jobs[0].target_id
        containers = []

        for job in jobs:
            containers.append(job.container_name)
            if job.status in killable_statuses:
                await worker_manager.kill_worker(job.container_name)
            job.status = "KILLED"
            job.last_seen = datetime.now(timezone.utc)

        await session.commit()

    # Push SSE event
    await push_task(f"events:{target_id}", {
        "event": "KILL_ALL",
        "target_id": target_id,
        "killed_count": len(containers),
        "containers": containers,
    })

    return {"success": True, "killed_count": len(containers), "containers": containers}
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_kill_rerun.py::test_kill_all_workers tests/test_kill_rerun.py::test_kill_idempotent -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_kill_rerun.py
git commit -m "feat: add POST /api/v1/kill endpoint for hard-kill all workers"
```

---

## Task 3: Backend — Rerun endpoint

**Files:**
- Modify: `orchestrator/main.py` (add endpoint + Pydantic model)
- Test: `tests/test_kill_rerun.py` (add tests)

**Step 1: Write the failing test**

Append to `tests/test_kill_rerun.py`:

```python
@pytest.mark.anyio
async def test_rerun_same_playbook(client, seed_target):
    """POST /api/v1/rerun with a valid playbook queues the target."""
    tid = seed_target
    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push, \
         patch("orchestrator.main.SHARED_CONFIG", new=__import__("pathlib").Path("/tmp/webbh_test_config")):
        import pathlib
        pathlib.Path(f"/tmp/webbh_test_config/{tid}").mkdir(parents=True, exist_ok=True)
        resp = await client.post("/api/v1/rerun", json={
            "target_id": tid,
            "playbook_name": "wide_recon",
        })
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["playbook_name"] == "wide_recon"

    # Verify last_playbook updated on target
    async with get_session() as session:
        from sqlalchemy import select
        t = (await session.execute(select(Target).where(Target.id == tid))).scalar_one()
        assert t.last_playbook == "wide_recon"


@pytest.mark.anyio
async def test_rerun_blocked_by_active_jobs(client, seed_running_jobs):
    """POST /api/v1/rerun returns 409 when jobs are active."""
    tid = seed_running_jobs
    resp = await client.post("/api/v1/rerun", json={
        "target_id": tid,
        "playbook_name": "wide_recon",
    })
    assert resp.status_code == 409


@pytest.mark.anyio
async def test_rerun_unknown_playbook(client, seed_target):
    """POST /api/v1/rerun with unknown playbook returns 404."""
    resp = await client.post("/api/v1/rerun", json={
        "target_id": seed_target,
        "playbook_name": "nonexistent_playbook",
    })
    assert resp.status_code == 404
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_kill_rerun.py::test_rerun_same_playbook tests/test_kill_rerun.py::test_rerun_blocked_by_active_jobs tests/test_kill_rerun.py::test_rerun_unknown_playbook -v`
Expected: FAIL — no route `/api/v1/rerun`.

**Step 3: Implement the rerun endpoint**

Add the Pydantic model near the other models (after `PlaybookUpdate` ~line 185):

```python
class RerunRequest(BaseModel):
    target_id: int = Field(..., gt=0)
    playbook_name: str = Field(..., min_length=1, max_length=100)
```

Add the endpoint after the kill endpoint:

```python
# ---------------------------------------------------------------------------
# POST /api/v1/rerun — rerun target with specified playbook
# ---------------------------------------------------------------------------
@app.post("/api/v1/rerun")
async def rerun_target(body: RerunRequest):
    """Re-queue a target with the specified playbook. Preserves existing data."""
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]

    async with get_session() as session:
        # Validate target exists
        target = (await session.execute(
            select(Target).where(Target.id == body.target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # Check no active jobs
        active = (await session.execute(
            select(func.count(JobState.id)).where(
                JobState.target_id == body.target_id,
                JobState.status.in_(active_statuses),
            )
        )).scalar()
        if active > 0:
            raise HTTPException(status_code=409, detail="Active jobs exist. Kill them first.")

        # Validate playbook
        from lib_webbh.playbooks import get_playbook, BUILTIN_PLAYBOOKS
        playbook_config = None
        if body.playbook_name in BUILTIN_PLAYBOOKS:
            playbook_config = BUILTIN_PLAYBOOKS[body.playbook_name]
        else:
            custom = (await session.execute(
                select(CustomPlaybook).where(CustomPlaybook.name == body.playbook_name)
            )).scalar_one_or_none()
            if custom:
                from lib_webbh.playbooks import PlaybookConfig, StageConfig, ConcurrencyConfig
                playbook_config = PlaybookConfig(
                    name=custom.name,
                    description=custom.description or "",
                    stages=[StageConfig(**s) for s in (custom.stages or [])],
                    concurrency=ConcurrencyConfig(**(custom.concurrency or {})),
                )

        if not playbook_config:
            raise HTTPException(status_code=404, detail=f"Playbook '{body.playbook_name}' not found")

        # Write playbook config
        profile_dir = SHARED_CONFIG / str(body.target_id)
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "playbook.json").write_text(
            json.dumps(playbook_config.to_dict(), indent=2)
        )

        # Update last_playbook
        target.last_playbook = body.playbook_name
        await session.commit()

    # Queue recon task
    await push_task("recon_queue", {
        "target_id": body.target_id,
        "action": "rerun",
    })

    # Push SSE event
    await push_task(f"events:{body.target_id}", {
        "event": "RERUN_STARTED",
        "target_id": body.target_id,
        "playbook_name": body.playbook_name,
    })

    return {"success": True, "target_id": body.target_id, "playbook_name": body.playbook_name}
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_kill_rerun.py::test_rerun_same_playbook tests/test_kill_rerun.py::test_rerun_blocked_by_active_jobs tests/test_kill_rerun.py::test_rerun_unknown_playbook -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_kill_rerun.py
git commit -m "feat: add POST /api/v1/rerun endpoint for target rerun with playbook"
```

---

## Task 4: Backend — Clean slate endpoint

**Files:**
- Modify: `orchestrator/main.py` (add endpoint)
- Test: `tests/test_kill_rerun.py` (add tests)

**Step 1: Write the failing test**

Append to `tests/test_kill_rerun.py`:

```python
@pytest_asyncio.fixture
async def seed_full_target(db):
    """Insert a target with assets, vulns, jobs, alerts — the full data set."""
    async with get_session() as session:
        t = Target(company_name="SlateTest", base_domain="slate.com", target_profile={})
        session.add(t)
        await session.flush()
        tid = t.id

        a = Asset(target_id=tid, asset_type="subdomain", asset_value="api.slate.com")
        session.add(a)
        await session.flush()

        session.add(Location(asset_id=a.id, port=443, protocol="tcp"))
        session.add(Vulnerability(target_id=tid, asset_id=a.id, severity="high", title="XSS"))
        session.add(JobState(target_id=tid, container_name=f"webbh-recon-t{tid}", status="COMPLETED", current_phase="done"))
        session.add(Alert(target_id=tid, alert_type="critical", message="test"))
        session.add(ScopeViolation(target_id=tid, tool_name="test", input_value="x", violation_type="domain"))
        # Also add a bounty (should survive clean slate)
        v2 = Vulnerability(target_id=tid, severity="medium", title="CSRF")
        session.add(v2)
        await session.flush()
        session.add(BountySubmission(target_id=tid, vulnerability_id=v2.id, platform="hackerone", status="submitted"))

        await session.commit()
        return tid


@pytest.mark.anyio
async def test_clean_slate(client, seed_full_target):
    """POST /api/v1/targets/{id}/clean-slate wipes data, preserves target + bounties."""
    tid = seed_full_target
    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock):
        resp = await client.post(f"/api/v1/targets/{tid}/clean-slate")
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    async with get_session() as session:
        from sqlalchemy import select, func
        # Target still exists
        t = (await session.execute(select(Target).where(Target.id == tid))).scalar_one()
        assert t is not None

        # All data wiped
        for model in [Asset, Vulnerability, JobState, Alert, Location, ScopeViolation]:
            count = (await session.execute(
                select(func.count()).select_from(model).where(model.target_id == tid)
                if hasattr(model, "target_id") else
                select(func.count()).select_from(model)
            )).scalar()
            assert count == 0, f"{model.__tablename__} should be empty but has {count} rows"

        # Bounties preserved
        bounty_count = (await session.execute(
            select(func.count()).select_from(BountySubmission).where(BountySubmission.target_id == tid)
        )).scalar()
        assert bounty_count == 1


@pytest.mark.anyio
async def test_clean_slate_blocked_by_active_jobs(client, seed_running_jobs):
    """POST /api/v1/targets/{id}/clean-slate returns 409 when jobs active."""
    tid = seed_running_jobs
    resp = await client.post(f"/api/v1/targets/{tid}/clean-slate")
    assert resp.status_code == 409
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_kill_rerun.py::test_clean_slate tests/test_kill_rerun.py::test_clean_slate_blocked_by_active_jobs -v`
Expected: FAIL — no route.

**Step 3: Implement the clean slate endpoint**

Add to `orchestrator/main.py` after the rerun endpoint:

```python
# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/clean-slate — wipe all target data
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/clean-slate")
async def clean_slate(target_id: int):
    """Delete all discovered data for a target. Preserves target, config, bounties."""
    from lib_webbh.database import (
        Vulnerability, Parameter, ApiSchema, Location, Observation,
        Identity, CloudAsset, AssetSnapshot, ScopeViolation, Alert,
        JobState, Asset, MobileApp,
    )
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]

    async with get_session() as session:
        # Validate target
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # Block if active jobs
        active = (await session.execute(
            select(func.count(JobState.id)).where(
                JobState.target_id == target_id,
                JobState.status.in_(active_statuses),
            )
        )).scalar()
        if active > 0:
            raise HTTPException(status_code=409, detail="Active jobs exist. Kill them first.")

        # Delete in dependency order — child tables first
        # Asset-child tables (need asset IDs first)
        from sqlalchemy import delete
        asset_ids_sub = select(Asset.id).where(Asset.target_id == target_id).scalar_subquery()
        await session.execute(delete(Vulnerability).where(Vulnerability.target_id == target_id))
        await session.execute(delete(Parameter).where(Parameter.asset_id.in_(select(Asset.id).where(Asset.target_id == target_id))))
        await session.execute(delete(ApiSchema).where(ApiSchema.target_id == target_id))
        await session.execute(delete(MobileApp).where(MobileApp.target_id == target_id))
        await session.execute(delete(Location).where(Location.asset_id.in_(select(Asset.id).where(Asset.target_id == target_id))))
        await session.execute(delete(Observation).where(Observation.asset_id.in_(select(Asset.id).where(Asset.target_id == target_id))))
        await session.execute(delete(Identity).where(Identity.target_id == target_id))
        await session.execute(delete(CloudAsset).where(CloudAsset.target_id == target_id))
        await session.execute(delete(AssetSnapshot).where(AssetSnapshot.target_id == target_id))
        await session.execute(delete(ScopeViolation).where(ScopeViolation.target_id == target_id))
        await session.execute(delete(Alert).where(Alert.target_id == target_id))
        await session.execute(delete(JobState).where(JobState.target_id == target_id))
        await session.execute(delete(Asset).where(Asset.target_id == target_id))

        await session.commit()

    # Push SSE event
    await push_task(f"events:{target_id}", {
        "event": "CLEAN_SLATE",
        "target_id": target_id,
    })

    return {"success": True, "target_id": target_id}
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_kill_rerun.py::test_clean_slate tests/test_kill_rerun.py::test_clean_slate_blocked_by_active_jobs -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_kill_rerun.py
git commit -m "feat: add POST /api/v1/targets/{id}/clean-slate endpoint"
```

---

## Task 5: Backend — Single-target enforcement + KILLED in event engine

**Files:**
- Modify: `orchestrator/main.py:303-348` (create_target endpoint)
- Modify: `orchestrator/event_engine.py:59` (ACTIVE_STATUSES)
- Test: `tests/test_kill_rerun.py` (add test)

**Step 1: Write the failing test**

Append to `tests/test_kill_rerun.py`:

```python
@pytest.mark.anyio
async def test_single_target_enforcement(client, seed_running_jobs):
    """POST /api/v1/targets returns 409 when another target has active jobs."""
    with patch("orchestrator.main._generate_tool_configs"):
        resp = await client.post("/api/v1/targets", json={
            "company_name": "NewCorp",
            "base_domain": "newcorp.com",
        })
    assert resp.status_code == 409
    assert "active" in resp.json()["detail"].lower()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_kill_rerun.py::test_single_target_enforcement -v`
Expected: FAIL — returns 201 (no enforcement yet).

**Step 3: Add single-target enforcement to create_target**

In `orchestrator/main.py`, at the start of `create_target()` (line 304, after `async def create_target(body: TargetCreate):`), add:

```python
    # Single-target enforcement — only one target may have active workers
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]
    async with get_session() as session:
        active_count = (await session.execute(
            select(func.count(JobState.id)).where(JobState.status.in_(active_statuses))
        )).scalar()
        if active_count > 0:
            raise HTTPException(
                status_code=409,
                detail="Another target is currently active. Stop it before starting a new target.",
            )
```

Also set `last_playbook` on target creation. In the same function, after `target = Target(...)` is created (~line 306-310), add `last_playbook=body.playbook` to the Target constructor:

```python
        target = Target(
            company_name=body.company_name,
            base_domain=body.base_domain,
            target_profile=body.target_profile,
            last_playbook=body.playbook,
        )
```

**Step 4: Add KILLED to event engine terminal statuses**

In `orchestrator/event_engine.py` line 59, the `ACTIVE_STATUSES` list is used to prevent re-triggering. `KILLED` jobs should NOT be considered active (they're terminal). No change needed to `ACTIVE_STATUSES` since `KILLED` isn't in it. However, `_check_recon_trigger()` (line 272-278) only filters on `COMPLETED` for the "don't re-trigger completed" check. A killed target should also not be re-triggered. Add `KILLED` alongside `COMPLETED`:

```python
        completed_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-recon-%"),
                JobState.status.in_(["COMPLETED", "KILLED"]),
            )
        ).subquery()
```

**Step 5: Run tests to verify they pass**

Run: `pytest tests/test_kill_rerun.py::test_single_target_enforcement -v`
Expected: PASS

**Step 6: Commit**

```bash
git add orchestrator/main.py orchestrator/event_engine.py tests/test_kill_rerun.py
git commit -m "feat: add single-target enforcement and KILLED status to event engine"
```

---

## Task 6: Dashboard — API client methods

**Files:**
- Modify: `dashboard/src/lib/api.ts` (add kill, rerun, cleanSlate methods)

**Step 1: Add new API response interfaces and methods**

In `dashboard/src/lib/api.ts`, add interfaces after the `SearchResult` interface (~line 205):

```typescript
/* ------------------------------------------------------------------ */
/* Kill / Rerun / Clean Slate                                          */
/* ------------------------------------------------------------------ */

interface KillResponse {
  success: boolean;
  killed_count: number;
  containers: string[];
}

interface RerunResponse {
  success: boolean;
  target_id: number;
  playbook_name: string;
}

interface CleanSlateResponse {
  success: boolean;
  target_id: number;
}
```

Add methods to the `api` object, after the `search` method (~line 482):

```typescript
  /* ------------------------------------------------------------------ */
  /* Kill / Rerun / Clean Slate                                          */
  /* ------------------------------------------------------------------ */

  kill() {
    return request<KillResponse>("/api/v1/kill", { method: "POST" });
  },

  rerun(targetId: number, playbookName: string) {
    return request<RerunResponse>("/api/v1/rerun", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId, playbook_name: playbookName }),
    });
  },

  cleanSlate(targetId: number) {
    return request<CleanSlateResponse>(`/api/v1/targets/${targetId}/clean-slate`, {
      method: "POST",
    });
  },
```

**Step 2: Commit**

```bash
git add dashboard/src/lib/api.ts
git commit -m "feat: add kill, rerun, cleanSlate API client methods"
```

---

## Task 7: Dashboard — SSE event types

**Files:**
- Modify: `dashboard/src/types/events.ts` (add new event types)

**Step 1: Add new SSE event types**

In `dashboard/src/types/events.ts`, add `KILL_ALL`, `RERUN_STARTED`, `CLEAN_SLATE` to the `SSEEventType` union (line 3-10):

```typescript
export type SSEEventType =
  | "TOOL_PROGRESS"
  | "NEW_ASSET"
  | "CRITICAL_ALERT"
  | "WORKER_SPAWNED"
  | "RECON_DIFF"
  | "SCOPE_DRIFT"
  | "AUTOSCALE_RECOMMENDATION"
  | "KILL_ALL"
  | "RERUN_STARTED"
  | "CLEAN_SLATE";
```

Add event interfaces at the end of the file:

```typescript
export interface KillAllEvent extends SSEEvent {
  event: "KILL_ALL";
  killed_count: number;
  containers: string[];
}

export interface RerunStartedEvent extends SSEEvent {
  event: "RERUN_STARTED";
  playbook_name: string;
}

export interface CleanSlateEvent extends SSEEvent {
  event: "CLEAN_SLATE";
}
```

**Step 2: Commit**

```bash
git add dashboard/src/types/events.ts
git commit -m "feat: add KILL_ALL, RERUN_STARTED, CLEAN_SLATE SSE event types"
```

---

## Task 8: Dashboard — Kill button in TopBar

**Files:**
- Modify: `dashboard/src/components/layout/TopBar.tsx`

**Step 1: Add kill button to TopBar**

In `dashboard/src/components/layout/TopBar.tsx`:

Add import for `Power` icon and `api` (api is already imported):

```typescript
import { ChevronDown, Wifi, WifiOff, Command, Power } from "lucide-react";
```

Add state for the kill confirmation dialog inside the `TopBar` component:

```typescript
const [killConfirmOpen, setKillConfirmOpen] = useState(false);
const [killing, setKilling] = useState(false);
```

Add the kill handler:

```typescript
async function handleKill() {
  setKilling(true);
  try {
    const res = await api.kill();
    setKillConfirmOpen(false);
    // Toast handled by live terminal / SSE
  } catch {
    /* error handled by API client */
  } finally {
    setKilling(false);
  }
}
```

In the JSX, add the kill button before the Command button in the right section (before line 101):

```tsx
<button
  onClick={() => setKillConfirmOpen(true)}
  className="flex items-center gap-1 rounded bg-danger/10 px-2 py-0.5 text-[10px] font-medium text-danger transition-colors hover:bg-danger/20"
  title="Kill all active operations"
>
  <Power className="h-3 w-3" />
  <span className="hidden sm:inline">KILL</span>
</button>
```

Add the confirmation dialog at the end of the component JSX (before the closing `</header>`):

```tsx
{killConfirmOpen && (
  <>
    <div className="fixed inset-0 z-50 bg-black/60" onClick={() => setKillConfirmOpen(false)} />
    <div className="fixed left-1/2 top-1/2 z-50 w-80 -translate-x-1/2 -translate-y-1/2 rounded-lg border border-danger/30 bg-bg-secondary p-5 shadow-xl">
      <h3 className="text-sm font-semibold text-text-primary">Kill All Operations</h3>
      <p className="mt-2 text-xs text-text-muted">
        This will immediately terminate all running workers. This cannot be undone.
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          onClick={() => setKillConfirmOpen(false)}
          className="rounded px-3 py-1.5 text-xs text-text-muted transition-colors hover:bg-bg-surface"
        >
          Cancel
        </button>
        <button
          onClick={handleKill}
          disabled={killing}
          className="rounded bg-danger px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-danger/90 disabled:opacity-50"
        >
          {killing ? "Killing..." : "Kill All"}
        </button>
      </div>
    </div>
  </>
)}
```

**Step 2: Commit**

```bash
git add dashboard/src/components/layout/TopBar.tsx
git commit -m "feat: add kill switch button to TopBar with confirmation dialog"
```

---

## Task 9: Dashboard — Rerun popover on C2 page

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx`

**Step 1: Add rerun popover to C2 page header**

In `dashboard/src/app/campaign/c2/page.tsx`:

Add imports:

```typescript
import { Activity, Columns2, Settings, RotateCcw } from "lucide-react";
import { api, type AssetWithLocations, type PlaybookRow } from "@/lib/api";
```

Add state inside `C2Page()`:

```typescript
const [rerunOpen, setRerunOpen] = useState(false);
const [rerunMode, setRerunMode] = useState<"menu" | "pick">("menu");
const [playbooks, setPlaybooks] = useState<PlaybookRow[]>([]);
const [rerunning, setRerunning] = useState(false);
```

Add the rerun handlers:

```typescript
const hasActiveJobs = jobs.some((j) =>
  ["RUNNING", "QUEUED", "PAUSED"].includes(j.status),
);

async function handleRerun(playbookName: string) {
  if (!activeTarget) return;
  setRerunning(true);
  try {
    await api.rerun(activeTarget.id, playbookName);
    setRerunOpen(false);
    setRerunMode("menu");
  } catch {
    /* error handled by API client */
  } finally {
    setRerunning(false);
  }
}

function openPlaybookPicker() {
  setRerunMode("pick");
  api.getPlaybooks().then((res) => setPlaybooks(res.playbooks)).catch(() => {});
}
```

In the page header JSX (the `div` with `ml-auto flex items-center gap-1` ~line 199), add the rerun button before the split-view button:

```tsx
{/* Rerun Popover */}
<div className="relative">
  <button
    onClick={() => { setRerunOpen(!rerunOpen); setRerunMode("menu"); }}
    disabled={hasActiveJobs}
    className="flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-accent transition-colors hover:bg-accent/10 disabled:cursor-not-allowed disabled:opacity-40"
    title={hasActiveJobs ? "Kill current run first" : "Rerun target"}
  >
    <RotateCcw className="h-3.5 w-3.5" />
    Rerun
  </button>
  {rerunOpen && !hasActiveJobs && (
    <div className="absolute right-0 top-full z-30 mt-1 w-56 rounded-md border border-border bg-bg-secondary shadow-lg animate-fade-in">
      {rerunMode === "menu" ? (
        <div className="p-1">
          <button
            onClick={() => handleRerun(activeTarget.last_playbook ?? "wide_recon")}
            disabled={rerunning}
            className="flex w-full flex-col items-start rounded px-3 py-2 text-left transition-colors hover:bg-bg-surface disabled:opacity-50"
          >
            <span className="text-xs font-medium text-text-primary">Same Playbook</span>
            <span className="text-[10px] text-text-muted font-mono">
              {activeTarget.last_playbook ?? "wide_recon"}
            </span>
          </button>
          <button
            onClick={openPlaybookPicker}
            className="flex w-full items-start rounded px-3 py-2 text-left text-xs font-medium text-text-primary transition-colors hover:bg-bg-surface"
          >
            Change Playbook
          </button>
        </div>
      ) : (
        <div className="max-h-64 overflow-y-auto p-1">
          {playbooks.map((pb) => (
            <button
              key={pb.id ?? pb.name}
              onClick={() => handleRerun(pb.name)}
              disabled={rerunning}
              className="flex w-full flex-col items-start rounded px-3 py-2 text-left transition-colors hover:bg-bg-surface disabled:opacity-50"
            >
              <span className="text-xs font-medium text-text-primary">{pb.name}</span>
              {pb.description && (
                <span className="text-[10px] text-text-muted line-clamp-1">{pb.description}</span>
              )}
            </button>
          ))}
          {playbooks.length === 0 && (
            <span className="block px-3 py-2 text-xs text-text-muted">Loading...</span>
          )}
        </div>
      )}
    </div>
  )}
</div>
```

**Step 2: Commit**

```bash
git add dashboard/src/app/campaign/c2/page.tsx
git commit -m "feat: add rerun popover with playbook selection to C2 page"
```

---

## Task 10: Dashboard — Clean slate in SettingsDrawer

**Files:**
- Modify: `dashboard/src/components/c2/SettingsDrawer.tsx`

**Step 1: Add danger zone to SettingsDrawer**

In `dashboard/src/components/c2/SettingsDrawer.tsx`:

Add `api` import (already imported) and new state:

```typescript
const [cleanSlateConfirm, setCleanSlateConfirm] = useState(false);
const [cleaning, setCleaning] = useState(false);
```

Add the `jobs` prop to the interface (need to know if active jobs exist):

```typescript
interface Props {
  open: boolean;
  onClose: () => void;
  targetId: number;
  currentProfile: TargetProfile | null;
  hasActiveJobs: boolean;
}
```

Update the function signature:

```typescript
export default function SettingsDrawer({ open, onClose, targetId, currentProfile, hasActiveJobs }: Props) {
```

Add the handler:

```typescript
async function handleCleanSlate() {
  setCleaning(true);
  try {
    await api.cleanSlate(targetId);
    setCleanSlateConfirm(false);
    onClose();
  } catch {
    /* error handled by API client */
  } finally {
    setCleaning(false);
  }
}
```

Add the Danger Zone section in the drawer body, after the Save button (~line 112):

```tsx
{/* Danger Zone */}
<div className="mt-8 border-t border-danger/20 pt-4">
  <span className="text-[10px] font-semibold uppercase tracking-wider text-danger/60">Danger Zone</span>
  <div className="mt-3">
    <button
      onClick={() => setCleanSlateConfirm(true)}
      disabled={hasActiveJobs}
      className="w-full rounded-md border border-danger/30 px-4 py-2 text-sm font-medium text-danger transition-colors hover:bg-danger/10 disabled:cursor-not-allowed disabled:opacity-40"
      title={hasActiveJobs ? "Kill current run first" : ""}
    >
      Reset Target Data
    </button>
    <p className="mt-1 text-[10px] text-text-muted">
      Deletes all assets, vulnerabilities, jobs, and alerts. Preserves configuration and bounties.
    </p>
  </div>
</div>

{/* Clean Slate Confirmation */}
{cleanSlateConfirm && (
  <>
    <div className="fixed inset-0 z-[60] bg-black/60" onClick={() => setCleanSlateConfirm(false)} />
    <div className="fixed left-1/2 top-1/2 z-[60] w-80 -translate-x-1/2 -translate-y-1/2 rounded-lg border border-danger/30 bg-bg-secondary p-5 shadow-xl">
      <h3 className="text-sm font-semibold text-text-primary">Reset Target Data</h3>
      <p className="mt-2 text-xs text-text-muted">
        This will permanently delete all discovered assets, vulnerabilities, jobs, and alerts for this target. Configuration and bounty submissions are preserved. This cannot be undone.
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          onClick={() => setCleanSlateConfirm(false)}
          className="rounded px-3 py-1.5 text-xs text-text-muted transition-colors hover:bg-bg-surface"
        >
          Cancel
        </button>
        <button
          onClick={handleCleanSlate}
          disabled={cleaning}
          className="rounded bg-danger px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-danger/90 disabled:opacity-50"
        >
          {cleaning ? "Resetting..." : "Delete All Data"}
        </button>
      </div>
    </div>
  </>
)}
```

**Step 2: Update the SettingsDrawer call in C2 page**

In `dashboard/src/app/campaign/c2/page.tsx`, update the `<SettingsDrawer>` usage (~line 276):

```tsx
<SettingsDrawer
  open={settingsOpen}
  onClose={() => setSettingsOpen(false)}
  targetId={activeTarget.id}
  currentProfile={activeTarget.target_profile}
  hasActiveJobs={hasActiveJobs}
/>
```

**Step 3: Commit**

```bash
git add dashboard/src/components/c2/SettingsDrawer.tsx dashboard/src/app/campaign/c2/page.tsx
git commit -m "feat: add clean slate danger zone to SettingsDrawer"
```

---

## Task 11: Dashboard — SSE event handlers in C2 page

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx` (handle new SSE events)

**Step 1: Add SSE event reactions**

In the C2 page's SSE merge effect (the `useEffect` that processes events, ~line 136-160), add handlers for the new event types. After the `NEW_ASSET` processing block:

```typescript
// Handle KILL_ALL — clear worker grid state
const killEvents = newEvents.filter((e) => e.event === "KILL_ALL");
if (killEvents.length > 0) {
  // Force refresh jobs (will show KILLED statuses)
  api.getStatus(activeTarget.id).then((res) => {
    setLocalJobs(res.jobs);
    setJobs(res.jobs);
  }).catch(() => {});
}

// Handle RERUN_STARTED — reset pipeline, refresh jobs
const rerunEvents = newEvents.filter((e) => e.event === "RERUN_STARTED");
if (rerunEvents.length > 0) {
  setLocalJobs([]);
  setJobs([]);
}

// Handle CLEAN_SLATE — reset everything
const cleanEvents = newEvents.filter((e) => e.event === "CLEAN_SLATE");
if (cleanEvents.length > 0) {
  setTreeRoots([]);
  setAllAssets([]);
  setLocalJobs([]);
  setJobs([]);
}
```

**Step 2: Commit**

```bash
git add dashboard/src/app/campaign/c2/page.tsx
git commit -m "feat: handle KILL_ALL, RERUN_STARTED, CLEAN_SLATE SSE events in C2"
```

---

## Task 12: Run full test suite

**Step 1: Run all kill/rerun tests**

Run: `pytest tests/test_kill_rerun.py -v`
Expected: All tests PASS.

**Step 2: Run existing orchestrator tests to verify no regressions**

Run: `pytest tests/test_main.py tests/test_event_engine.py tests/test_bounty_tracker.py tests/test_scheduling.py -v`
Expected: All PASS.

**Step 3: Run dashboard lint**

Run: `cd dashboard && npm run lint`
Expected: No errors.

**Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "test: verify kill switch, rerun, clean slate features"
```

---

## Summary of all files changed

### New files
- `tests/test_kill_rerun.py` — Tests for all 3 endpoints + single-target enforcement

### Modified files — Backend
- `shared/lib_webbh/database.py` — `last_playbook` column on Target
- `orchestrator/main.py` — 3 new endpoints (`kill`, `rerun`, `clean-slate`), single-target enforcement on `create_target`, `RerunRequest` model
- `orchestrator/event_engine.py` — `KILLED` added to completed status check in `_check_recon_trigger`

### Modified files — Dashboard
- `dashboard/src/types/schema.ts` — `KILLED` in JobStatus, `last_playbook` on Target
- `dashboard/src/types/events.ts` — 3 new event types
- `dashboard/src/lib/api.ts` — `kill()`, `rerun()`, `cleanSlate()` methods
- `dashboard/src/components/layout/TopBar.tsx` — Kill button + confirmation dialog
- `dashboard/src/app/campaign/c2/page.tsx` — Rerun popover + SSE handlers
- `dashboard/src/components/c2/SettingsDrawer.tsx` — Danger zone with clean slate
