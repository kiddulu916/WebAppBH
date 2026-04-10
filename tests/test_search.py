# tests/test_search.py
"""Tests for the global search endpoint (GET /api/v1/search)."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Asset, Vulnerability, get_engine, get_session


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
async def populated_target(db):
    async with get_session() as s:
        t = Target(company_name="SearchTest", base_domain="search.com")
        s.add(t)
        await s.flush()
        s.add(Asset(target_id=t.id, asset_type="subdomain", asset_value="api.search.com", source_tool="test"))
        s.add(Asset(target_id=t.id, asset_type="subdomain", asset_value="admin.search.com", source_tool="test"))
        s.add(Vulnerability(target_id=t.id, severity="high", title="SQL Injection on api.search.com"))
        s.add(Vulnerability(target_id=t.id, severity="medium", title="XSS in admin panel", description="Stored XSS found in admin.search.com"))
        await s.commit()
        await s.refresh(t)
        return t.id


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.EventEngine") as MockEventEngine:
        mock_engine_instance = MagicMock()
        mock_engine_instance.run = AsyncMock()
        MockEventEngine.return_value = mock_engine_instance
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        yield AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


@pytest.mark.anyio
async def test_search_assets(client, populated_target):
    res = await client.get(f"/api/v1/search?target_id={populated_target}&q=api")
    assert res.status_code == 200
    data = res.json()
    assert len(data["results"]) >= 1
    assert any(r["value"] == "api.search.com" for r in data["results"])


@pytest.mark.anyio
async def test_search_vulns(client, populated_target):
    res = await client.get(f"/api/v1/search?target_id={populated_target}&q=SQL")
    assert res.status_code == 200
    data = res.json()
    assert any(r["type"] == "vulnerability" for r in data["results"])


@pytest.mark.anyio
async def test_search_min_length(client, db):
    res = await client.get("/api/v1/search?target_id=1&q=a")
    assert res.status_code == 422  # min_length=2


@pytest.mark.anyio
async def test_search_no_results(client, populated_target):
    res = await client.get(f"/api/v1/search?target_id={populated_target}&q=nonexistent_term_xyz")
    assert res.status_code == 200
    assert len(res.json()["results"]) == 0


@pytest.mark.anyio
async def test_search_returns_both_types(client, populated_target):
    """Searching for 'admin' should match both assets and vulns."""
    res = await client.get(f"/api/v1/search?target_id={populated_target}&q=admin")
    assert res.status_code == 200
    data = res.json()
    types = {r["type"] for r in data["results"]}
    assert "asset" in types
    assert "vulnerability" in types


@pytest.mark.anyio
async def test_search_vuln_description(client, populated_target):
    """Searching should also match vulnerability descriptions."""
    res = await client.get(f"/api/v1/search?target_id={populated_target}&q=Stored XSS")
    assert res.status_code == 200
    data = res.json()
    assert any(r["type"] == "vulnerability" and r["value"] == "XSS in admin panel" for r in data["results"])
