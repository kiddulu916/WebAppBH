# tests/test_playbook_api.py
"""Test playbook selection via the target creation API."""

import os
import json
import pytest
from unittest.mock import AsyncMock, patch

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from lib_webbh.database import get_engine, Base

# Patch event_engine background tasks before importing app
with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock), \
     patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock), \
     patch("orchestrator.event_engine.run_redis_listener", new_callable=AsyncMock), \
     patch("orchestrator.event_engine.run_autoscaler", new_callable=AsyncMock):
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


@pytest.mark.asyncio
async def test_create_target_with_playbook(db, client, tmp_path):
    """POST with explicit playbook should persist it and return it."""
    with patch("orchestrator.main.SHARED_CONFIG", tmp_path):
        resp = await client.post(
            "/api/v1/targets",
            json={"company_name": "TestCo", "base_domain": "test.com", "playbook": "deep_webapp"},
            headers=API_KEY_HEADER,
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["playbook"] == "deep_webapp"

    # Verify playbook.json was written to the config directory
    tid = data["target_id"]
    playbook_path = tmp_path / str(tid) / "playbook.json"
    assert playbook_path.exists()
    playbook_data = json.loads(playbook_path.read_text())
    assert playbook_data["name"] == "deep_webapp"


@pytest.mark.asyncio
async def test_create_target_default_playbook(db, client, tmp_path):
    """POST without playbook should default to wide_recon."""
    with patch("orchestrator.main.SHARED_CONFIG", tmp_path):
        resp = await client.post(
            "/api/v1/targets",
            json={"company_name": "TestCo2", "base_domain": "test2.com"},
            headers=API_KEY_HEADER,
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["playbook"] == "wide_recon"

    # Verify playbook.json was written with default
    tid = data["target_id"]
    playbook_path = tmp_path / str(tid) / "playbook.json"
    assert playbook_path.exists()
    playbook_data = json.loads(playbook_path.read_text())
    assert playbook_data["name"] == "wide_recon"


@pytest.mark.asyncio
async def test_create_target_unknown_playbook_falls_back(db, client, tmp_path):
    """POST with unknown playbook name should fall back to wide_recon."""
    with patch("orchestrator.main.SHARED_CONFIG", tmp_path):
        resp = await client.post(
            "/api/v1/targets",
            json={"company_name": "TestCo3", "base_domain": "test3.com", "playbook": "nonexistent"},
            headers=API_KEY_HEADER,
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["playbook"] == "wide_recon"
