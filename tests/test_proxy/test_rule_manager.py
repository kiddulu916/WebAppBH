# tests/test_proxy/test_rule_manager.py
import pytest

pytestmark = pytest.mark.anyio


async def test_rule_manager_crud():
    from workers.proxy.rule_manager import create_app
    from aiohttp.test_utils import TestClient, TestServer

    app = create_app()
    async with TestClient(TestServer(app)) as client:
        # POST — create rule
        resp = await client.post("/rules", json={
            "match": {"url_pattern": "*/api/*"},
            "transform": {"type": "inject_header", "header": "X-Test", "value": "1"},
        })
        assert resp.status == 201
        data = await resp.json()
        rule_id = data["id"]

        # GET — list rules
        resp = await client.get("/rules")
        assert resp.status == 200
        rules = await resp.json()
        assert len(rules) == 1

        # DELETE — remove rule
        resp = await client.delete(f"/rules/{rule_id}")
        assert resp.status == 200

        # Verify deleted
        resp = await client.get("/rules")
        rules = await resp.json()
        assert len(rules) == 0
