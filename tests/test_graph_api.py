# tests/test_graph_api.py
"""Test GET /api/v1/targets/{target_id}/graph endpoint."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Asset, Location, Vulnerability, get_engine, get_session


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
async def seed_graph_data(db):
    """Create target + asset + location + vuln for graph testing."""
    async with get_session() as session:
        t = Target(company_name="GraphCo", base_domain="graph.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.graph.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        loc = Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="open")
        session.add(loc)
        await session.commit()
        await session.refresh(loc)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="SQL Injection", description="SQLi in login", source_tool="sqlmap",
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)

        return {"target_id": t.id, "asset_id": a.id, "loc_id": loc.id, "vuln_id": v.id}


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
async def test_graph_returns_nodes_and_edges(client, seed_graph_data):
    tid = seed_graph_data["target_id"]
    resp = await client.get(f"/api/v1/targets/{tid}/graph")
    assert resp.status_code == 200
    body = resp.json()

    # Expect: 1 target + 1 asset + 1 location + 1 vuln = 4 nodes
    assert len(body["nodes"]) == 4
    # Expect: target->asset + asset->location + asset->vuln = 3 edges
    assert len(body["edges"]) == 3

    node_types = {n["type"] for n in body["nodes"]}
    assert "target" in node_types
    assert "domain" in node_types
    assert "port" in node_types
    assert "vulnerability" in node_types


@pytest.mark.anyio
async def test_graph_empty_target(client, db):
    """Target with no assets should return just the target node."""
    async with get_session() as session:
        t = Target(company_name="EmptyGraph", base_domain="empty-graph.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        tid = t.id

    resp = await client.get(f"/api/v1/targets/{tid}/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) == 1
    assert body["nodes"][0]["type"] == "target"
    assert len(body["edges"]) == 0


@pytest.mark.anyio
async def test_graph_unknown_target(client, db):
    resp = await client.get("/api/v1/targets/9999/graph")
    assert resp.status_code == 404
