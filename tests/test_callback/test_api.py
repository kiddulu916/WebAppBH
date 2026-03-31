# tests/test_callback/test_api.py
import pytest

pytestmark = pytest.mark.anyio


async def test_callback_api_register_and_poll():
    from workers.callback.api import create_app
    from aiohttp.test_utils import TestClient, TestServer

    app = create_app()
    async with TestClient(TestServer(app)) as client:
        # Register
        resp = await client.post("/callbacks", json={"protocols": ["http", "dns"]})
        assert resp.status == 201
        data = await resp.json()
        cb_id = data["id"]

        # Poll — no interactions yet
        resp = await client.get(f"/callbacks/{cb_id}")
        assert resp.status == 200
        data = await resp.json()
        assert data["interactions"] == []

        # Simulate an interaction arriving (via internal record endpoint)
        resp = await client.post(f"/callbacks/{cb_id}/interaction", json={
            "protocol": "http",
            "source_ip": "10.0.0.1",
            "data": "GET / HTTP/1.1",
        })
        assert resp.status == 200

        # Poll again — one interaction
        resp = await client.get(f"/callbacks/{cb_id}")
        data = await resp.json()
        assert len(data["interactions"]) == 1

        # Cleanup
        resp = await client.delete(f"/callbacks/{cb_id}")
        assert resp.status == 200
