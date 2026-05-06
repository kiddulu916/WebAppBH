"""Tests for asset classification and association chain API endpoints."""

import os

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"
os.environ["RATE_LIMIT_FAIL_OPEN"] = "1"

import tests._patch_logger  # noqa: F401

from lib_webbh.database import get_engine, get_session, Base, Target, Asset


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(company_name="TestCo", base_domain="testco.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


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
async def test_list_assets_includes_classification(client, seed_target):
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target, asset_type="domain",
            asset_value="api.testco.com", source_tool="subfinder",
            scope_classification="in-scope",
        )
        session.add(asset)
        await session.commit()

    resp = await client.get(f"/api/v1/assets?target_id={seed_target}")
    assert resp.status_code == 200
    assets = resp.json()["assets"]
    assert len(assets) == 1
    assert assets[0]["scope_classification"] == "in-scope"


@pytest.mark.anyio
async def test_list_assets_filter_by_classification(client, seed_target):
    async with get_session() as session:
        a1 = Asset(target_id=seed_target, asset_type="domain",
                   asset_value="a.testco.com", source_tool="test",
                   scope_classification="in-scope")
        a2 = Asset(target_id=seed_target, asset_type="domain",
                   asset_value="b.testco.com", source_tool="test",
                   scope_classification="pending")
        session.add_all([a1, a2])
        await session.commit()

    resp = await client.get(f"/api/v1/assets?target_id={seed_target}&classification=in-scope")
    assert resp.status_code == 200
    assets = resp.json()["assets"]
    assert len(assets) == 1
    assert assets[0]["asset_value"] == "a.testco.com"


@pytest.mark.anyio
async def test_update_single_asset_classification(client, seed_target):
    async with get_session() as session:
        asset = Asset(target_id=seed_target, asset_type="domain",
                      asset_value="test.com", source_tool="test",
                      scope_classification="pending")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        asset_id = asset.id

    resp = await client.put(
        f"/api/v1/assets/{asset_id}/classification",
        json={"classification": "in-scope"},
    )
    assert resp.status_code == 200
    assert resp.json()["scope_classification"] == "in-scope"

    # Verify persisted
    async with get_session() as session:
        updated = await session.get(Asset, asset_id)
        assert updated.scope_classification == "in-scope"


@pytest.mark.anyio
async def test_update_classification_invalid_value(client, seed_target):
    async with get_session() as session:
        asset = Asset(target_id=seed_target, asset_type="domain",
                      asset_value="test.com", source_tool="test")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        asset_id = asset.id

    resp = await client.put(
        f"/api/v1/assets/{asset_id}/classification",
        json={"classification": "invalid-value"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_bulk_update_classification(client, seed_target):
    async with get_session() as session:
        a1 = Asset(target_id=seed_target, asset_type="domain",
                   asset_value="a.testco.com", source_tool="test",
                   scope_classification="pending")
        a2 = Asset(target_id=seed_target, asset_type="domain",
                   asset_value="b.testco.com", source_tool="test",
                   scope_classification="pending")
        session.add_all([a1, a2])
        await session.commit()
        await session.refresh(a1)
        await session.refresh(a2)
        ids = [a1.id, a2.id]

    resp = await client.put(
        "/api/v1/assets/bulk-classification",
        json={"asset_ids": ids, "classification": "out-of-scope"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 2

    async with get_session() as session:
        for aid in ids:
            asset = await session.get(Asset, aid)
            assert asset.scope_classification == "out-of-scope"


@pytest.mark.anyio
async def test_get_asset_chain(client, seed_target):
    async with get_session() as session:
        root = Asset(target_id=seed_target, asset_type="domain",
                     asset_value="testco.com", source_tool="manual")
        session.add(root)
        await session.flush()
        child = Asset(target_id=seed_target, asset_type="domain",
                      asset_value="api.testco.com", source_tool="subfinder",
                      associated_with_id=root.id, association_method="dns_resolution")
        session.add(child)
        await session.flush()
        grandchild = Asset(target_id=seed_target, asset_type="ip",
                           asset_value="10.0.0.1", source_tool="dns",
                           associated_with_id=child.id, association_method="a_record")
        session.add(grandchild)
        await session.commit()
        await session.refresh(grandchild)
        gc_id = grandchild.id

    resp = await client.get(f"/api/v1/assets/{gc_id}/chain")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert len(chain) == 3
    assert chain[0]["asset_value"] == "10.0.0.1"
    assert chain[1]["asset_value"] == "api.testco.com"
    assert chain[2]["asset_value"] == "testco.com"
    assert chain[0]["association_method"] == "a_record"


@pytest.mark.anyio
async def test_get_asset_chain_no_parent(client, seed_target):
    async with get_session() as session:
        asset = Asset(target_id=seed_target, asset_type="domain",
                      asset_value="standalone.com", source_tool="manual")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        aid = asset.id

    resp = await client.get(f"/api/v1/assets/{aid}/chain")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert len(chain) == 1
    assert chain[0]["asset_value"] == "standalone.com"
