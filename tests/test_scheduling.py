# tests/test_scheduling.py
"""Tests for Target Scheduling API (CRUD + event engine integration)."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, ScheduledScan, get_engine, get_session


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
        t = Target(company_name="ScheduleTest", base_domain="schedule.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_redis_listener", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_autoscaler", new_callable=AsyncMock):
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


# --------------------------------------------------------------------------
# POST /api/v1/schedules
# --------------------------------------------------------------------------
@pytest.mark.anyio
async def test_create_schedule(client, seed_target):
    resp = await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "0 2 * * *",
        "playbook": "wide_recon",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["target_id"] == seed_target
    assert body["cron_expression"] == "0 2 * * *"
    assert body["playbook"] == "wide_recon"
    assert body["enabled"] is True
    assert body["next_run_at"] is not None
    assert "id" in body


@pytest.mark.anyio
async def test_create_schedule_invalid_cron(client, seed_target):
    resp = await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "bad",
    })
    assert resp.status_code == 400
    assert "Invalid cron" in resp.json()["detail"]


@pytest.mark.anyio
async def test_create_schedule_target_not_found(client, db):
    resp = await client.post("/api/v1/schedules", json={
        "target_id": 99999,
        "cron_expression": "0 2 * * *",
    })
    assert resp.status_code == 404
    assert "Target not found" in resp.json()["detail"]


# --------------------------------------------------------------------------
# GET /api/v1/schedules
# --------------------------------------------------------------------------
@pytest.mark.anyio
async def test_list_schedules(client, seed_target):
    await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "0 2 * * *",
    })
    await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "0 6 * * 1",
    })
    resp = await client.get("/api/v1/schedules")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 2


@pytest.mark.anyio
async def test_list_schedules_by_target(client, db):
    # Create two targets
    async with get_session() as session:
        t1 = Target(company_name="A", base_domain="a.com")
        t2 = Target(company_name="B", base_domain="b.com")
        session.add_all([t1, t2])
        await session.commit()
        await session.refresh(t1)
        await session.refresh(t2)
        tid1, tid2 = t1.id, t2.id

    await client.post("/api/v1/schedules", json={
        "target_id": tid1,
        "cron_expression": "0 2 * * *",
    })
    await client.post("/api/v1/schedules", json={
        "target_id": tid2,
        "cron_expression": "0 6 * * 1",
    })

    resp1 = await client.get("/api/v1/schedules", params={"target_id": tid1})
    assert resp1.status_code == 200
    assert len(resp1.json()) == 1
    assert resp1.json()[0]["target_id"] == tid1

    resp2 = await client.get("/api/v1/schedules", params={"target_id": tid2})
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1
    assert resp2.json()[0]["target_id"] == tid2


# --------------------------------------------------------------------------
# PATCH /api/v1/schedules/{schedule_id}
# --------------------------------------------------------------------------
@pytest.mark.anyio
async def test_update_schedule_disable(client, seed_target):
    create_resp = await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "0 2 * * *",
    })
    schedule_id = create_resp.json()["id"]

    patch_resp = await client.patch(f"/api/v1/schedules/{schedule_id}", json={
        "enabled": False,
    })
    assert patch_resp.status_code == 200
    body = patch_resp.json()
    assert body["enabled"] is False


@pytest.mark.anyio
async def test_update_schedule_cron(client, seed_target):
    create_resp = await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "0 2 * * *",
    })
    schedule_id = create_resp.json()["id"]
    original_next = create_resp.json()["next_run_at"]

    patch_resp = await client.patch(f"/api/v1/schedules/{schedule_id}", json={
        "cron_expression": "0 12 * * *",
    })
    assert patch_resp.status_code == 200
    body = patch_resp.json()
    assert body["cron_expression"] == "0 12 * * *"
    # next_run_at should have been recalculated
    assert body["next_run_at"] is not None
    assert body["next_run_at"] != original_next or body["cron_expression"] == "0 12 * * *"


@pytest.mark.anyio
async def test_update_schedule_not_found(client, db):
    resp = await client.patch("/api/v1/schedules/99999", json={"enabled": False})
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# DELETE /api/v1/schedules/{schedule_id}
# --------------------------------------------------------------------------
@pytest.mark.anyio
async def test_delete_schedule(client, seed_target):
    create_resp = await client.post("/api/v1/schedules", json={
        "target_id": seed_target,
        "cron_expression": "0 2 * * *",
    })
    schedule_id = create_resp.json()["id"]

    del_resp = await client.delete(f"/api/v1/schedules/{schedule_id}")
    assert del_resp.status_code == 204

    # Verify it's gone
    list_resp = await client.get("/api/v1/schedules")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 0


@pytest.mark.anyio
async def test_delete_schedule_not_found(client, db):
    resp = await client.delete("/api/v1/schedules/99999")
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# Unit test: _check_scheduled_scans
# --------------------------------------------------------------------------
@pytest.mark.anyio
async def test_check_scheduled_scans(db):
    """Create a ScheduledScan with next_run_at in the past, call _check_scheduled_scans,
    verify it updates last_run_at and next_run_at."""
    from lib_webbh.cron_utils import next_run as compute_next

    # Create target and scheduled scan
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    async with get_session() as session:
        t = Target(company_name="CronTest", base_domain="cron.com")
        session.add(t)
        await session.flush()

        scan = ScheduledScan(
            target_id=t.id,
            cron_expression="0 * * * *",  # every hour
            playbook="wide_recon",
            enabled=True,
            next_run_at=past,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        scan_id = scan.id

    with patch("orchestrator.event_engine.push_task", new_callable=AsyncMock) as mock_push:
        from orchestrator.event_engine import _check_scheduled_scans
        await _check_scheduled_scans()

        # Verify push_task was called
        mock_push.assert_called_once()
        call_args = mock_push.call_args
        assert call_args[0][0] == "recon_queue"
        payload = call_args[0][1]
        assert payload["rescan"] is True
        assert payload["scheduled"] is True
        assert payload["playbook"] == "wide_recon"

    # Verify DB was updated
    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(ScheduledScan).where(ScheduledScan.id == scan_id)
        )
        updated = result.scalar_one()
        assert updated.last_run_at is not None
        assert updated.next_run_at is not None
        # next_run_at should be in the future now
        now = datetime.now(timezone.utc)
        # Handle naive datetimes from SQLite
        next_at = updated.next_run_at
        if next_at.tzinfo is None:
            next_at = next_at.replace(tzinfo=timezone.utc)
        assert next_at > now - timedelta(minutes=5)  # should be roughly in the future
