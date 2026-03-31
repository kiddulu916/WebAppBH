# tests/test_database_target_hierarchy.py
import pytest

pytestmark = pytest.mark.anyio


async def test_target_has_campaign_id(db_session):
    from lib_webbh.database import Target, Campaign

    campaign = Campaign(name="Test")
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    target = Target(
        company_name="TestCo",
        base_domain="target.com",
        campaign_id=campaign.id,
        target_type="seed",
        priority=100,
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.campaign_id == campaign.id
    assert target.target_type == "seed"
    assert target.priority == 100
    assert target.wildcard is False
    assert target.wildcard_count is None
    assert target.parent_target_id is None


async def test_target_parent_child_relationship(db_session):
    from lib_webbh.database import Target

    parent = Target(company_name="TestCo", base_domain="target.com", target_type="seed")
    db_session.add(parent)
    await db_session.commit()
    await db_session.refresh(parent)

    child = Target(
        company_name="TestCo",
        base_domain="api.target.com",
        parent_target_id=parent.id,
        target_type="child",
        priority=85,
    )
    db_session.add(child)
    await db_session.commit()
    await db_session.refresh(child)

    assert child.parent_target_id == parent.id
    assert child.target_type == "child"

    # Refresh parent to load children relationship
    await db_session.refresh(parent, ["children"])
    assert len(parent.children) == 1
    assert parent.children[0].base_domain == "api.target.com"


async def test_target_wildcard(db_session):
    from lib_webbh.database import Target

    target = Target(
        company_name="TestCo",
        base_domain="*.target.com",
        wildcard=True,
        wildcard_count=50,
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.wildcard is True
    assert target.wildcard_count == 50


async def test_target_defaults(db_session):
    from lib_webbh.database import Target

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.target_type == "seed"
    assert target.priority == 50
    assert target.wildcard is False
