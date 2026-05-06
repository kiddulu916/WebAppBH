"""Tests for multi-round campaign expansion in info_gathering worker."""

import os

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"

import tests._patch_logger  # noqa: F401

from lib_webbh.database import get_engine, get_session, Base, Target, Asset, Campaign


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_campaign(db):
    """Create a campaign + target with base_domain."""
    async with get_session() as session:
        campaign = Campaign(name="Test Campaign")
        session.add(campaign)
        await session.flush()

        target = Target(
            company_name="TestCo", base_domain="testco.com",
            campaign_id=campaign.id,
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)
        return target.id, campaign.id


@pytest.mark.anyio
async def test_expansion_queues_in_scope_discoveries(seed_campaign):
    """New in-scope assets discovered in round 1 get queued for round 2."""
    target_id, _ = seed_campaign

    # Add an in-scope domain asset (simulating discovery by pipeline)
    async with get_session() as session:
        asset = Asset(
            target_id=target_id, asset_type="domain",
            asset_value="api.testco.com", source_tool="subfinder",
            scope_classification="in-scope",
        )
        session.add(asset)
        await session.commit()

    from workers.info_gathering.main import _run_expansion

    with patch("workers.info_gathering.main.push_task", new_callable=AsyncMock) as mock_push:
        await _run_expansion(target_id)

        # Should have queued the new asset + emitted events
        queue_calls = [c for c in mock_push.call_args_list
                       if c[0][0] == "info_gathering_queue"]
        assert len(queue_calls) == 1
        assert queue_calls[0][0][1]["domain"] == "api.testco.com"
        assert queue_calls[0][0][1]["expansion_round"] == 1


@pytest.mark.anyio
async def test_expansion_queues_associated_discoveries(seed_campaign):
    """Associated assets also get queued for pipeline runs."""
    target_id, _ = seed_campaign

    async with get_session() as session:
        asset = Asset(
            target_id=target_id, asset_type="ip",
            asset_value="10.0.0.1", source_tool="dns",
            scope_classification="associated",
        )
        session.add(asset)
        await session.commit()

    from workers.info_gathering.main import _run_expansion

    with patch("workers.info_gathering.main.push_task", new_callable=AsyncMock) as mock_push:
        await _run_expansion(target_id)

        queue_calls = [c for c in mock_push.call_args_list
                       if c[0][0] == "info_gathering_queue"]
        assert len(queue_calls) == 1


@pytest.mark.anyio
async def test_undetermined_assets_not_queued(seed_campaign):
    """Undetermined assets are NOT auto-queued."""
    target_id, _ = seed_campaign

    async with get_session() as session:
        asset = Asset(
            target_id=target_id, asset_type="domain",
            asset_value="unknown.com", source_tool="dork_engine",
            scope_classification="undetermined",
        )
        session.add(asset)
        await session.commit()

    from workers.info_gathering.main import _run_expansion

    with patch("workers.info_gathering.main.push_task", new_callable=AsyncMock) as mock_push:
        await _run_expansion(target_id)

        queue_calls = [c for c in mock_push.call_args_list
                       if c[0][0] == "info_gathering_queue"]
        assert len(queue_calls) == 0


@pytest.mark.anyio
async def test_convergence_stops_expansion(seed_campaign):
    """Expansion stops when no new in-scope/associated assets found."""
    target_id, _ = seed_campaign

    # No new assets — should converge immediately
    from workers.info_gathering.main import _run_expansion

    with patch("workers.info_gathering.main.push_task", new_callable=AsyncMock) as mock_push:
        await _run_expansion(target_id)

        event_calls = [c for c in mock_push.call_args_list
                       if c[0][0] == f"events:{target_id}"]
        events = [c[0][1] for c in event_calls]
        assert any(e["event"] == "CAMPAIGN_COMPLETE" and e["reason"] == "converged" for e in events)


@pytest.mark.anyio
async def test_max_rounds_safeguard(seed_campaign):
    """Expansion stops after max_rounds."""
    target_id, _ = seed_campaign

    from workers.info_gathering import main as main_mod
    from workers.info_gathering.main import _run_expansion

    round_counter = [0]

    original_get_targets = main_mod._get_expansion_targets

    async def mock_get_targets(tid, scanned):
        round_counter[0] += 1
        # Always return a new fake asset so expansion never converges
        mock_asset = Asset(
            target_id=tid, asset_type="domain",
            asset_value=f"round{round_counter[0]}.testco.com",
            source_tool="test", scope_classification="in-scope",
        )
        return [mock_asset]

    with patch("workers.info_gathering.main.push_task", new_callable=AsyncMock) as mock_push:
        with patch.object(main_mod, "_get_expansion_targets", side_effect=mock_get_targets):
            await _run_expansion(target_id)

        event_calls = [c for c in mock_push.call_args_list
                       if c[0][0] == f"events:{target_id}"]
        events = [c[0][1] for c in event_calls]

        round_events = [e for e in events if e["event"] == "ROUND_COMPLETE"]
        assert len(round_events) == main_mod.MAX_EXPANSION_ROUNDS

        assert any(e["event"] == "CAMPAIGN_COMPLETE" and e["reason"] == "max_rounds" for e in events)


@pytest.mark.anyio
async def test_deduplication(seed_campaign):
    """An asset is never scanned twice."""
    target_id, _ = seed_campaign

    async with get_session() as session:
        asset = Asset(
            target_id=target_id, asset_type="domain",
            asset_value="api.testco.com", source_tool="subfinder",
            scope_classification="in-scope",
        )
        session.add(asset)
        await session.commit()

    from workers.info_gathering.main import _run_expansion

    with patch("workers.info_gathering.main.push_task", new_callable=AsyncMock) as mock_push:
        await _run_expansion(target_id)

        queue_calls = [c for c in mock_push.call_args_list
                       if c[0][0] == "info_gathering_queue"]
        queued_domains = [c[0][1].get("domain") for c in queue_calls]
        # No duplicates
        assert len(queued_domains) == len(set(queued_domains))
