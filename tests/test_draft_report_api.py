# tests/test_draft_report_api.py
"""Test GET /api/v1/vulnerabilities/{vuln_id}/draft endpoint."""

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
async def seed_vuln(db):
    async with get_session() as session:
        t = Target(company_name="DraftCo", base_domain="draft.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.draft.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="XSS in Search", description="Reflected XSS found",
            poc="<script>alert(1)</script>", source_tool="nuclei", cvss_score=7.5,
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        return v.id


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
async def test_draft_report_hackerone(client, seed_vuln):
    resp = await client.get(f"/api/v1/vulnerabilities/{seed_vuln}/draft?platform=hackerone")
    assert resp.status_code == 200
    body = resp.json()
    assert body["vuln_id"] == seed_vuln
    assert body["platform"] == "hackerone"
    assert "## Summary" in body["draft"]
    assert "XSS in Search" in body["draft"]


@pytest.mark.anyio
async def test_draft_report_bugcrowd(client, seed_vuln):
    resp = await client.get(f"/api/v1/vulnerabilities/{seed_vuln}/draft?platform=bugcrowd")
    assert resp.status_code == 200
    body = resp.json()
    assert body["platform"] == "bugcrowd"
    assert "## Vulnerability:" in body["draft"]


@pytest.mark.anyio
async def test_draft_report_unknown_vuln(client, db):
    resp = await client.get("/api/v1/vulnerabilities/9999/draft")
    assert resp.status_code == 404
