# tests/test_queue_health_api.py
"""Test GET /api/v1/queue_health endpoint."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import tests._patch_logger  # noqa: F401


@pytest.fixture
def anyio_backend():
    return "asyncio"


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
async def test_queue_health_returns_all_queues(client):
    with patch("lib_webbh.messaging.get_pending", new_callable=AsyncMock, return_value={"pending": 10}):
        resp = await client.get("/api/v1/queue_health")
    assert resp.status_code == 200
    body = resp.json()
    assert "queues" in body
    assert "recon_queue" in body["queues"]
    assert body["queues"]["recon_queue"]["health"] == "healthy"


@pytest.mark.anyio
async def test_queue_health_pressure(client):
    with patch("lib_webbh.messaging.get_pending", new_callable=AsyncMock, return_value={"pending": 120}):
        resp = await client.get("/api/v1/queue_health")
    body = resp.json()
    assert body["queues"]["recon_queue"]["health"] == "pressure"


@pytest.mark.anyio
async def test_queue_health_redis_error(client):
    with patch("lib_webbh.messaging.get_pending", new_callable=AsyncMock, side_effect=Exception("redis down")):
        resp = await client.get("/api/v1/queue_health")
    assert resp.status_code == 200
    body = resp.json()
    # Should fall back to 0 pending = IDLE
    assert body["queues"]["recon_queue"]["health"] == "idle"
