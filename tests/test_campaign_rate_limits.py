"""Tests for Campaign rate_limits JSON field."""

import pytest
from sqlalchemy import inspect
from lib_webbh import Campaign


def test_campaign_has_rate_limits_column():
    mapper = inspect(Campaign)
    columns = {c.key for c in mapper.columns}
    assert "rate_limits" in columns


@pytest.mark.anyio
async def test_campaign_rate_limits_default(db_session):
    campaign = Campaign(name="Test Campaign")
    db_session.add(campaign)
    await db_session.flush()
    assert campaign.rate_limits == [{"amount": 50, "unit": "req/s"}]


@pytest.mark.anyio
async def test_campaign_rate_limits_custom(db_session):
    rules = [
        {"amount": 20, "unit": "req/s"},
        {"amount": 1000, "unit": "req/min"},
    ]
    campaign = Campaign(name="Custom", rate_limits=rules)
    db_session.add(campaign)
    await db_session.flush()
    assert campaign.rate_limits == rules
    assert len(campaign.rate_limits) == 2


@pytest.mark.anyio
async def test_campaign_rate_limits_null_allowed(db_session):
    campaign = Campaign(name="No limits", rate_limits=None)
    db_session.add(campaign)
    await db_session.flush()
    assert campaign.rate_limits is None
