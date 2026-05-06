"""Tests for API key management endpoints including Censys support."""

import os

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"
os.environ["RATE_LIMIT_FAIL_OPEN"] = "1"

import tests._patch_logger  # noqa: F401

from lib_webbh.database import get_engine, Base


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest.fixture(autouse=True)
def _clean_intel_keys():
    """Save and restore intel API key state to prevent test pollution."""
    import lib_webbh.intel_enrichment as intel_mod
    saved_env = {}
    saved_mod = {}
    for key in ("SHODAN_API_KEY", "SECURITYTRAILS_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"):
        saved_env[key] = os.environ.get(key, "")
        saved_mod[key] = getattr(intel_mod, key, "")
    yield
    for key in ("SHODAN_API_KEY", "SECURITYTRAILS_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"):
        os.environ[key] = saved_env[key]
        setattr(intel_mod, key, saved_mod[key])


@pytest.fixture
def client(db):
    with patch("orchestrator.event_engine.EventEngine") as MockEventEngine:
        mock_engine_instance = MagicMock()
        mock_engine_instance.run = AsyncMock()
        MockEventEngine.return_value = mock_engine_instance
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-KEY": "test-api-key-1234"},
        )


@pytest.mark.anyio
async def test_get_api_key_status_includes_censys(client):
    resp = await client.get("/api/v1/config/api_keys")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert "censys" in keys
    assert "shodan" in keys
    assert "securitytrails" in keys


@pytest.mark.anyio
async def test_put_api_keys_accepts_censys(client):
    resp = await client.put("/api/v1/config/api_keys", json={
        "censys_api_id": "test-id",
        "censys_api_secret": "test-secret",
    })
    assert resp.status_code == 200
    assert resp.json()["keys"]["censys"] is True


@pytest.mark.anyio
async def test_put_empty_string_does_not_overwrite(client):
    # Set a key first
    await client.put("/api/v1/config/api_keys", json={"shodan_api_key": "real-key"})
    # Send empty string — should not overwrite
    await client.put("/api/v1/config/api_keys", json={"shodan_api_key": ""})
    resp = await client.get("/api/v1/config/api_keys")
    assert resp.json()["keys"]["shodan"] is True
