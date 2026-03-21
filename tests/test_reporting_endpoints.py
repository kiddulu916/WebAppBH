# tests/test_reporting_endpoints.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Vulnerability, Asset, get_engine, get_session


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
async def seed_target_with_vuln(db):
    async with get_session() as session:
        t = Target(company_name="ReportCorp", base_domain="report.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.report.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="Test Vuln", description="Test", poc="test poc", source_tool="test",
        )
        session.add(v)
        await session.commit()
        return t.id


@pytest_asyncio.fixture
async def seed_empty_target(db):
    async with get_session() as session:
        t = Target(company_name="EmptyCorp", base_domain="empty.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock):
        with patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock):
            with patch("orchestrator.event_engine.run_redis_listener", new_callable=AsyncMock):
                from httpx import ASGITransport, AsyncClient
                from orchestrator.main import app
                transport = ASGITransport(app=app)
                return AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


@pytest.mark.anyio
async def test_create_report_pushes_to_queue(client, seed_target_with_vuln):
    with patch("orchestrator.main.push_task", new_callable=AsyncMock, return_value="msg-123") as mock_push:
        resp = await client.post(
            f"/api/v1/targets/{seed_target_with_vuln}/reports",
            json={"formats": ["hackerone_md"], "platform": "hackerone"},
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued"
    mock_push.assert_called_once()
    call_args = mock_push.call_args
    assert call_args[0][0] == "report_queue"


@pytest.mark.anyio
async def test_create_report_rejects_no_vulns(client, seed_empty_target):
    resp = await client.post(
        f"/api/v1/targets/{seed_empty_target}/reports",
        json={"formats": ["hackerone_md"], "platform": "hackerone"},
    )
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_create_report_rejects_unknown_target(client, db):
    resp = await client.post(
        "/api/v1/targets/9999/reports",
        json={"formats": ["hackerone_md"], "platform": "hackerone"},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_list_reports_empty(client, seed_target_with_vuln):
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("orchestrator.main.SHARED_REPORTS", new=__import__('pathlib').Path(tmpdir)):
            resp = await client.get(f"/api/v1/targets/{seed_target_with_vuln}/reports")
    assert resp.status_code == 200
    assert "reports" in resp.json()
