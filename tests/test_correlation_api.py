# tests/test_correlation_api.py
"""Test GET /api/v1/targets/{target_id}/correlations endpoint."""

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
async def seed_correlated_vulns(db):
    async with get_session() as session:
        t = Target(company_name="CorrCo", base_domain="corr.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.corr.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        v1 = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="XSS in Search", source_tool="dalfox", cvss_score=7.5,
        )
        v2 = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="critical",
            title="SQLi in Login", source_tool="sqlmap", cvss_score=9.8,
        )
        session.add_all([v1, v2])
        await session.commit()
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
        return AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


@pytest.mark.anyio
async def test_correlations_groups_by_asset(client, seed_correlated_vulns):
    resp = await client.get(f"/api/v1/targets/{seed_correlated_vulns}/correlations")
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_id"] == seed_correlated_vulns
    assert len(body["groups"]) >= 1
    group = body["groups"][0]
    assert "app.corr.com" in group["shared_assets"]
    assert group["count"] == 2


@pytest.mark.anyio
async def test_correlations_empty_target(client, db):
    async with get_session() as session:
        t = Target(company_name="EmptyCorr", base_domain="empty-corr.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        tid = t.id

    resp = await client.get(f"/api/v1/targets/{tid}/correlations")
    assert resp.status_code == 200
    assert resp.json()["groups"] == []


@pytest.mark.anyio
async def test_correlations_unknown_target(client, db):
    resp = await client.get("/api/v1/targets/9999/correlations")
    assert resp.status_code == 404
