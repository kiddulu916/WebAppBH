# tests/test_main.py
"""Tests for orchestrator.main — FastAPI endpoints."""

import os
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from lib_webbh.database import get_engine, Base, get_session, Target, JobState, Asset, Location

# Patch event_engine background tasks before importing app
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


# --- Fix 3: always write config files ---

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


# --- Fix 4: container name validation + auth warning ---

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


# --- Fix 13: SSE pending message cleanup ---

@pytest.mark.asyncio
async def test_sse_generator_cleans_up_on_disconnect():
    """The SSE generator should release pending messages on disconnect."""
    from unittest.mock import AsyncMock, MagicMock
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


# --- Phase 3: GET endpoints ---

@pytest.mark.asyncio
async def test_get_targets_returns_all(db, client):
    async with get_session() as session:
        session.add(Target(company_name="Corp1", base_domain="corp1.com"))
        session.add(Target(company_name="Corp2", base_domain="corp2.com"))
        await session.commit()

    resp = await client.get("/api/v1/targets", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["targets"]) == 2
    names = {t["company_name"] for t in data["targets"]}
    assert names == {"Corp1", "Corp2"}


@pytest.mark.asyncio
async def test_get_targets_empty(db, client):
    resp = await client.get("/api/v1/targets", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    assert resp.json()["targets"] == []


@pytest.mark.asyncio
async def test_get_assets_requires_target_id(db, client):
    resp = await client.get("/api/v1/assets", headers=API_KEY_HEADER)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_assets_returns_with_locations(db, client):
    async with get_session() as session:
        t = Target(company_name="AssetCorp", base_domain="asset.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="sub.asset.com", source_tool="amass")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        session.add(Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="open"))
        await session.commit()

    resp = await client.get(f"/api/v1/assets?target_id={t.id}", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    assets = resp.json()["assets"]
    assert len(assets) == 1
    assert assets[0]["asset_value"] == "sub.asset.com"
    assert len(assets[0]["locations"]) == 1
    assert assets[0]["locations"][0]["port"] == 443
