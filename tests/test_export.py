# tests/test_export.py
"""Tests for GET /api/v1/targets/{target_id}/export endpoint."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Asset, Vulnerability, get_engine, get_session


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
async def seed_vulns(db):
    async with get_session() as session:
        t = Target(company_name="ExportTest", base_domain="export.com")
        session.add(t)
        await session.flush()
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="app.export.com")
        session.add(a)
        await session.flush()
        v1 = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="critical",
            title="SQL Injection", source_tool="sqlmap", cvss_score=9.8,
        )
        v2 = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="XSS", source_tool="nuclei", cvss_score=7.5,
        )
        v3 = Vulnerability(
            target_id=t.id, severity="low",
            title="Info Disclosure", source_tool="ffuf",
        )
        session.add_all([v1, v2, v3])
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
        return AsyncClient(
            transport=transport, base_url="http://test",
            headers={"X-API-KEY": "test-api-key-1234"},
        )


@pytest.mark.anyio
async def test_export_json(client, seed_vulns):
    resp = await client.get(f"/api/v1/targets/{seed_vulns}/export")
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_id"] == seed_vulns
    assert body["count"] == 3
    assert len(body["vulnerabilities"]) == 3


@pytest.mark.anyio
async def test_export_csv(client, seed_vulns):
    resp = await client.get(f"/api/v1/targets/{seed_vulns}/export?format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    lines = resp.text.strip().split("\n")
    # header + 3 data rows
    assert len(lines) == 4
    assert "severity" in lines[0]
    assert "SQL Injection" in resp.text


@pytest.mark.anyio
async def test_export_markdown(client, seed_vulns):
    resp = await client.get(f"/api/v1/targets/{seed_vulns}/export?format=markdown")
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "| ID | Severity |" in resp.text
    assert "SQL Injection" in resp.text


@pytest.mark.anyio
async def test_export_filter_severity(client, seed_vulns):
    resp = await client.get(f"/api/v1/targets/{seed_vulns}/export?severity=critical")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["vulnerabilities"][0]["severity"] == "critical"
    assert body["vulnerabilities"][0]["title"] == "SQL Injection"


@pytest.mark.anyio
async def test_export_empty_target(client, db):
    # Create a target with no vulns
    async with get_session() as session:
        t = Target(company_name="EmptyCo", base_domain="empty.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        tid = t.id

    resp = await client.get(f"/api/v1/targets/{tid}/export")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 0
    assert body["vulnerabilities"] == []
