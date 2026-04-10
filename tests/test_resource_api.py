# tests/test_resource_api.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

import tests._patch_logger  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
def _reset_redis():
    """Reset the Redis singleton so stale connections don't leak across event loops."""
    import lib_webbh.messaging as _msg
    _msg._redis = None
    yield
    _msg._redis = None


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.EventEngine") as MockEventEngine, \
         patch("orchestrator.main.rate_limit_check", new_callable=AsyncMock):
        mock_engine_instance = MagicMock()
        mock_engine_instance.run = AsyncMock()
        MockEventEngine.return_value = mock_engine_instance
        from orchestrator.main import app
        from orchestrator.resource_guard import ResourceGuard
        from orchestrator.routes.resources import set_guard
        set_guard(ResourceGuard())
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


async def test_get_resource_status(client):
    resp = await client.get("/api/v1/resources/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "tier" in data


async def test_override_resource_tier(client):
    resp = await client.post("/api/v1/resources/override", json={"tier": "red"})
    assert resp.status_code == 200

    resp = await client.get("/api/v1/resources/status")
    data = resp.json()
    assert data["tier"] == "red"

    # Clear override
    resp = await client.post("/api/v1/resources/override", json={"tier": None})
    assert resp.status_code == 200
