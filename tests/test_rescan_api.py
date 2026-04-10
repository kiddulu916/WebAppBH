# tests/test_rescan_api.py
"""Test POST /api/v1/targets/{target_id}/rescan endpoint."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Asset, get_engine, get_session


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
async def seed_target_with_assets(db):
    async with get_session() as session:
        t = Target(company_name="RescanCo", base_domain="rescan.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.rescan.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        return t.id


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.EventEngine") as MockEventEngine:
        mock_engine_instance = MagicMock()
        mock_engine_instance.run = AsyncMock()
        MockEventEngine.return_value = mock_engine_instance
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


@pytest.mark.anyio
async def test_trigger_rescan_returns_201_queued(client, seed_target_with_assets):
    with patch("orchestrator.main.push_task", new_callable=AsyncMock, return_value="msg-rescan") as mock_push:
        resp = await client.post(f"/api/v1/targets/{seed_target_with_assets}/rescan")
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued"
    assert body["scan_number"] == 1
    assert body["target_id"] == seed_target_with_assets
    mock_push.assert_called_once()
    call_args = mock_push.call_args
    assert call_args[0][0] == "recon_queue"
    assert call_args[0][1]["rescan"] is True


@pytest.mark.anyio
async def test_trigger_rescan_increments_scan_number(client, seed_target_with_assets):
    with patch("orchestrator.main.push_task", new_callable=AsyncMock, return_value="msg-1"):
        resp1 = await client.post(f"/api/v1/targets/{seed_target_with_assets}/rescan")
    assert resp1.json()["scan_number"] == 1

    with patch("orchestrator.main.push_task", new_callable=AsyncMock, return_value="msg-2"):
        resp2 = await client.post(f"/api/v1/targets/{seed_target_with_assets}/rescan")
    assert resp2.json()["scan_number"] == 2


@pytest.mark.anyio
async def test_trigger_rescan_unknown_target(client, db):
    with patch("orchestrator.main.push_task", new_callable=AsyncMock):
        resp = await client.post("/api/v1/targets/9999/rescan")
    assert resp.status_code == 404
