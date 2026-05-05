"""Tests for scope classification integration in the pipeline."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from lib_webbh.scope import ScopeManager


@pytest.mark.anyio
async def test_save_asset_sets_classification_via_scope_manager(db_session):
    """Assets saved via base_tool.save_asset() should have scope_classification set."""
    from lib_webbh import Target
    from workers.info_gathering.base_tool import InfoGatheringTool

    # Create a concrete subclass for testing
    class TestTool(InfoGatheringTool):
        async def execute(self, target_id, **kwargs):
            return {"found": 0}

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()

    sm = ScopeManager(in_scope=["*.test.com", "test.com"], out_of_scope=["staging.test.com"])
    tool = TestTool()

    # In-scope asset
    asset_id = await tool.save_asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="api.test.com",
        source_tool="test",
        scope_manager=sm,
    )
    assert asset_id is not None

    from lib_webbh import Asset, get_session
    async with get_session() as session:
        asset = await session.get(Asset, asset_id)
        assert asset.scope_classification == "in-scope"


@pytest.mark.anyio
async def test_save_asset_out_of_scope(db_session):
    """Out-of-scope assets should be classified as out-of-scope."""
    from lib_webbh import Target
    from workers.info_gathering.base_tool import InfoGatheringTool

    class TestTool(InfoGatheringTool):
        async def execute(self, target_id, **kwargs):
            return {"found": 0}

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()

    sm = ScopeManager(in_scope=["*.test.com"], out_of_scope=["staging.test.com"])
    tool = TestTool()

    asset_id = await tool.save_asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="staging.test.com",
        source_tool="test",
        scope_manager=sm,
    )
    assert asset_id is not None

    from lib_webbh import Asset, get_session
    async with get_session() as session:
        asset = await session.get(Asset, asset_id)
        assert asset.scope_classification == "out-of-scope"


@pytest.mark.anyio
async def test_save_asset_pending_when_unknown(db_session):
    """Unknown assets should be classified as pending."""
    from lib_webbh import Target
    from workers.info_gathering.base_tool import InfoGatheringTool

    class TestTool(InfoGatheringTool):
        async def execute(self, target_id, **kwargs):
            return {"found": 0}

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()

    sm = ScopeManager(in_scope=["*.test.com"], out_of_scope=[])
    tool = TestTool()

    asset_id = await tool.save_asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="unknown.other.com",
        source_tool="test",
        scope_manager=sm,
    )
    assert asset_id is not None

    from lib_webbh import Asset, get_session
    async with get_session() as session:
        asset = await session.get(Asset, asset_id)
        assert asset.scope_classification == "pending"


@pytest.mark.anyio
async def test_save_asset_defaults_pending_without_scope_manager(db_session):
    """Without a scope_manager, assets default to pending."""
    from lib_webbh import Target
    from workers.info_gathering.base_tool import InfoGatheringTool

    class TestTool(InfoGatheringTool):
        async def execute(self, target_id, **kwargs):
            return {"found": 0}

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()

    tool = TestTool()
    asset_id = await tool.save_asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="test.com",
        source_tool="test",
    )
    assert asset_id is not None

    from lib_webbh import Asset, get_session
    async with get_session() as session:
        asset = await session.get(Asset, asset_id)
        assert asset.scope_classification == "pending"
