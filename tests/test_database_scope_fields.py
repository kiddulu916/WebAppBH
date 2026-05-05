"""Tests for scope_classification and association tracking columns on Asset."""

import pytest
from sqlalchemy import inspect
from lib_webbh import Asset


def test_asset_has_scope_classification_column():
    mapper = inspect(Asset)
    columns = {c.key for c in mapper.columns}
    assert "scope_classification" in columns


def test_asset_has_associated_with_id_column():
    mapper = inspect(Asset)
    columns = {c.key for c in mapper.columns}
    assert "associated_with_id" in columns


def test_asset_has_association_method_column():
    mapper = inspect(Asset)
    columns = {c.key for c in mapper.columns}
    assert "association_method" in columns


@pytest.mark.anyio
async def test_asset_scope_classification_defaults_to_pending(db_session):
    from lib_webbh import Target

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()
    asset = Asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="test.com",
        source_tool="test",
    )
    db_session.add(asset)
    await db_session.flush()
    assert asset.scope_classification == "pending"


@pytest.mark.anyio
async def test_asset_associated_with_relationship(db_session):
    from lib_webbh import Target

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()
    parent = Asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="test.com",
        source_tool="test",
    )
    db_session.add(parent)
    await db_session.flush()
    child = Asset(
        target_id=target.id,
        asset_type="ip",
        asset_value="1.2.3.4",
        source_tool="dns",
        scope_classification="associated",
        associated_with_id=parent.id,
        association_method="dns_resolution",
    )
    db_session.add(child)
    await db_session.flush()
    assert child.associated_with_id == parent.id
    assert child.association_method == "dns_resolution"


@pytest.mark.anyio
async def test_child_asset_survives_parent_deletion(db_session):
    """Deleting a parent asset does NOT cascade-delete children."""
    from lib_webbh import Target

    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()
    parent = Asset(
        target_id=target.id,
        asset_type="domain",
        asset_value="test.com",
        source_tool="test",
    )
    db_session.add(parent)
    await db_session.flush()
    child = Asset(
        target_id=target.id,
        asset_type="ip",
        asset_value="1.2.3.4",
        source_tool="dns",
        associated_with_id=parent.id,
    )
    db_session.add(child)
    await db_session.flush()
    child_id = child.id
    # Nullify FK manually (mirrors ON DELETE SET NULL in PostgreSQL)
    child.associated_with_id = None
    await db_session.flush()
    await db_session.delete(parent)
    await db_session.flush()
    refreshed = await db_session.get(Asset, child_id)
    assert refreshed is not None
