# tests/test_database_campaign.py
import pytest
from datetime import datetime, timezone

pytestmark = pytest.mark.anyio


async def test_create_campaign(db_session):
    from lib_webbh.database import Campaign

    campaign = Campaign(
        name="Test Campaign",
        description="Testing the campaign model",
        status="pending",
        scope_config={"in_scope": ["*.target.com"]},
        rate_limit=50,
        has_credentials=False,
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    assert campaign.id is not None
    assert campaign.name == "Test Campaign"
    assert campaign.status == "pending"
    assert campaign.scope_config == {"in_scope": ["*.target.com"]}
    assert campaign.rate_limit == 50
    assert campaign.has_credentials is False
    assert campaign.started_at is None
    assert campaign.completed_at is None
    assert isinstance(campaign.created_at, datetime)


async def test_campaign_defaults(db_session):
    from lib_webbh.database import Campaign

    campaign = Campaign(name="Minimal Campaign")
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    assert campaign.status == "pending"
    assert campaign.rate_limit == 50
    assert campaign.has_credentials is False
