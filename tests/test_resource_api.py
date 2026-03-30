# tests/test_resource_api.py
import pytest
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.anyio


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