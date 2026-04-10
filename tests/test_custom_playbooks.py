# tests/test_custom_playbooks.py
"""Tests for Custom Playbook CRUD API."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, get_engine, get_session
from lib_webbh.playbooks import BUILTIN_PLAYBOOKS


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


SAMPLE_PLAYBOOK = {
    "name": "custom_stealth",
    "description": "Low-noise stealth recon",
    "stages": [
        {"name": "passive_discovery", "enabled": True, "tool_timeout": 300},
        {"name": "liveness_dns", "enabled": True, "tool_timeout": 120},
    ],
    "concurrency": {"heavy": 1, "light": 2},
}


@pytest.mark.anyio
async def test_create_playbook(client, db):
    resp = await client.post("/api/v1/playbooks", json=SAMPLE_PLAYBOOK)
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "custom_stealth"
    assert body["description"] == "Low-noise stealth recon"
    assert body["stages"] == SAMPLE_PLAYBOOK["stages"]
    assert body["concurrency"] == {"heavy": 1, "light": 2}
    assert body["builtin"] is False
    assert "id" in body


@pytest.mark.anyio
async def test_create_playbook_duplicate_name(client, db):
    resp1 = await client.post("/api/v1/playbooks", json=SAMPLE_PLAYBOOK)
    assert resp1.status_code == 201

    resp2 = await client.post("/api/v1/playbooks", json=SAMPLE_PLAYBOOK)
    assert resp2.status_code == 409


@pytest.mark.anyio
async def test_list_playbooks(client, db):
    # Create a custom playbook first
    await client.post("/api/v1/playbooks", json=SAMPLE_PLAYBOOK)

    resp = await client.get("/api/v1/playbooks")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)

    # Should contain all built-in + the custom one
    names = [p["name"] for p in body]
    for builtin_name in BUILTIN_PLAYBOOKS:
        assert builtin_name in names

    assert "custom_stealth" in names

    # Verify builtin flag
    for p in body:
        if p["name"] in BUILTIN_PLAYBOOKS:
            assert p["builtin"] is True
        else:
            assert p["builtin"] is False
            assert "id" in p


@pytest.mark.anyio
async def test_update_playbook(client, db):
    create_resp = await client.post("/api/v1/playbooks", json=SAMPLE_PLAYBOOK)
    playbook_id = create_resp.json()["id"]

    patch_resp = await client.patch(f"/api/v1/playbooks/{playbook_id}", json={
        "description": "Updated stealth recon",
        "stages": [
            {"name": "passive_discovery", "enabled": True, "tool_timeout": 600},
        ],
    })
    assert patch_resp.status_code == 200
    body = patch_resp.json()
    assert body["description"] == "Updated stealth recon"
    assert len(body["stages"]) == 1
    assert body["stages"][0]["tool_timeout"] == 600
    # Concurrency should remain unchanged
    assert body["concurrency"] == {"heavy": 1, "light": 2}


@pytest.mark.anyio
async def test_update_playbook_not_found(client, db):
    resp = await client.patch("/api/v1/playbooks/99999", json={
        "description": "Does not exist",
    })
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_delete_playbook(client, db):
    create_resp = await client.post("/api/v1/playbooks", json=SAMPLE_PLAYBOOK)
    playbook_id = create_resp.json()["id"]

    del_resp = await client.delete(f"/api/v1/playbooks/{playbook_id}")
    assert del_resp.status_code == 204

    # Verify it's gone from the list
    list_resp = await client.get("/api/v1/playbooks")
    names = [p["name"] for p in list_resp.json()]
    assert "custom_stealth" not in names


@pytest.mark.anyio
async def test_delete_playbook_not_found(client, db):
    resp = await client.delete("/api/v1/playbooks/99999")
    assert resp.status_code == 404
