# tests/test_campaign_api.py
import os
import pytest
from httpx import AsyncClient, ASGITransport

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401

import pytest_asyncio
from lib_webbh.database import get_engine, Base, Campaign

# Patch event_engine background tasks before importing app
from unittest.mock import patch
with patch("orchestrator.rate_limit.rate_limit_check"):
    from orchestrator.main import app

pytestmark = pytest.mark.anyio


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


API_KEY_HEADER = {"X-API-KEY": "test-api-key-1234"}


async def test_create_campaign(client):
    resp = await client.post("/api/v1/campaigns", json={
        "name": "Test Campaign",
        "targets": [{"domain": "target.com"}],
        "scope_config": {"in_scope": ["*.target.com"]},
    }, headers=API_KEY_HEADER)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Campaign"
    assert data["id"] is not None


async def test_list_campaigns(client):
    await client.post("/api/v1/campaigns", json={
        "name": "Campaign 1",
        "targets": [{"domain": "a.com"}],
    }, headers=API_KEY_HEADER)
    resp = await client.get("/api/v1/campaigns", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1