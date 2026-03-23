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
    Alert, ApiSchema, ScopeViolation, BountySubmission, MobileApp,
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
         patch("orchestrator.event_engine.run_autoscaler", new_callable=AsyncMock), \
         patch("orchestrator.rate_limit.rate_limit_check", new_callable=AsyncMock):
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(
            transport=transport, base_url="http://test",
            headers={"X-API-KEY": "test-api-key-1234"},
        )


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


@pytest.mark.anyio
async def test_kill_all_workers(client, seed_running_jobs):
    """POST /api/v1/kill should SIGKILL all active containers and mark jobs KILLED."""
    tid = seed_running_jobs
    with patch("orchestrator.worker_manager.kill_worker", new_callable=AsyncMock, return_value=True) as mock_kill, \
         patch("orchestrator.main.push_task", new_callable=AsyncMock):
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
    with patch("orchestrator.main.push_task", new_callable=AsyncMock):
        resp = await client.post("/api/v1/kill")
    assert resp.status_code == 200
    assert resp.json()["killed_count"] == 0


@pytest.mark.anyio
async def test_rerun_same_playbook(client, seed_target):
    """POST /api/v1/rerun with a valid playbook queues the target."""
    tid = seed_target
    with patch("orchestrator.main.push_task", new_callable=AsyncMock) as mock_push, \
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
    with patch("orchestrator.main.push_task", new_callable=AsyncMock):
        resp = await client.post(f"/api/v1/targets/{tid}/clean-slate")
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    async with get_session() as session:
        from sqlalchemy import select, func
        # Target still exists
        t = (await session.execute(select(Target).where(Target.id == tid))).scalar_one()
        assert t is not None

        # Assets wiped
        asset_count = (await session.execute(
            select(func.count()).select_from(Asset).where(Asset.target_id == tid)
        )).scalar()
        assert asset_count == 0

        # Vulns wiped (except the one referenced by bounty)
        vuln_count = (await session.execute(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.target_id == tid)
        )).scalar()
        assert vuln_count == 1  # CSRF vuln preserved (referenced by bounty)

        # Jobs wiped
        job_count = (await session.execute(
            select(func.count()).select_from(JobState).where(JobState.target_id == tid)
        )).scalar()
        assert job_count == 0

        # Alerts wiped
        alert_count = (await session.execute(
            select(func.count()).select_from(Alert).where(Alert.target_id == tid)
        )).scalar()
        assert alert_count == 0

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
