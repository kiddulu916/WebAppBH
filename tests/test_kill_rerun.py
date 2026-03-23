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
