# tests/test_bounty_tracker.py
"""Tests for Bounty Tracker API (CRUD + stats)."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Vulnerability, BountySubmission, get_engine, get_session


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
async def seed_vuln(db):
    async with get_session() as session:
        t = Target(company_name="BountyTest", base_domain="bounty.com")
        session.add(t)
        await session.flush()
        v = Vulnerability(target_id=t.id, severity="high", title="XSS in login")
        session.add(v)
        await session.commit()
        await session.refresh(t)
        await session.refresh(v)
        return t.id, v.id


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


@pytest.mark.anyio
async def test_create_bounty(client, seed_vuln):
    target_id, vuln_id = seed_vuln
    resp = await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "hackerone",
        "expected_payout": 500.0,
        "notes": "XSS on login page",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["target_id"] == target_id
    assert body["vulnerability_id"] == vuln_id
    assert body["platform"] == "hackerone"
    assert body["status"] == "submitted"
    assert body["expected_payout"] == 500.0
    assert body["notes"] == "XSS on login page"
    assert body["actual_payout"] is None
    assert "id" in body


@pytest.mark.anyio
async def test_list_bounties(client, seed_vuln):
    target_id, vuln_id = seed_vuln
    await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "hackerone",
    })
    resp = await client.get("/api/v1/bounties")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) >= 1
    assert body[0]["platform"] == "hackerone"


@pytest.mark.anyio
async def test_list_bounties_by_status(client, seed_vuln):
    target_id, vuln_id = seed_vuln
    await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "hackerone",
        "status": "submitted",
    })
    await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "bugcrowd",
        "status": "accepted",
    })

    resp_submitted = await client.get("/api/v1/bounties", params={"status": "submitted"})
    assert resp_submitted.status_code == 200
    submitted = resp_submitted.json()
    assert all(b["status"] == "submitted" for b in submitted)
    assert len(submitted) == 1

    resp_accepted = await client.get("/api/v1/bounties", params={"status": "accepted"})
    assert resp_accepted.status_code == 200
    accepted = resp_accepted.json()
    assert all(b["status"] == "accepted" for b in accepted)
    assert len(accepted) == 1


@pytest.mark.anyio
async def test_update_bounty(client, seed_vuln):
    target_id, vuln_id = seed_vuln
    create_resp = await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "hackerone",
        "status": "submitted",
    })
    bounty_id = create_resp.json()["id"]

    patch_resp = await client.patch(f"/api/v1/bounties/{bounty_id}", json={
        "status": "accepted",
        "actual_payout": 750.0,
    })
    assert patch_resp.status_code == 200
    body = patch_resp.json()
    assert body["status"] == "accepted"
    assert body["actual_payout"] == 750.0


@pytest.mark.anyio
async def test_bounty_stats(client, seed_vuln):
    target_id, vuln_id = seed_vuln
    # Create several bounties
    await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "hackerone",
        "status": "submitted",
    })
    resp2 = await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "hackerone",
        "status": "accepted",
        "expected_payout": 500.0,
    })
    bounty2_id = resp2.json()["id"]
    # Update with actual payout
    await client.patch(f"/api/v1/bounties/{bounty2_id}", json={
        "actual_payout": 500.0,
    })

    await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": vuln_id,
        "platform": "bugcrowd",
        "status": "accepted",
    })

    resp = await client.get("/api/v1/bounties/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_submitted"] == 3
    assert stats["total_accepted"] == 2
    assert stats["total_paid"] == 1
    assert stats["total_payout"] == 500.0
    assert stats["by_platform"]["hackerone"] == 2
    assert stats["by_platform"]["bugcrowd"] == 1
    assert str(target_id) in stats["by_target"]  # JSON keys are strings
    assert stats["by_target"][str(target_id)] == 500.0


@pytest.mark.anyio
async def test_create_bounty_invalid_vuln(client, db):
    # Create a target but no vulnerability
    async with get_session() as session:
        t = Target(company_name="NoVuln", base_domain="novuln.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        target_id = t.id

    resp = await client.post("/api/v1/bounties", json={
        "target_id": target_id,
        "vulnerability_id": 99999,
        "platform": "hackerone",
    })
    assert resp.status_code == 404
    assert "Vulnerability not found" in resp.json()["detail"]
