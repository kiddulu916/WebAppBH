# tests/test_event_engine.py
"""Tests for orchestrator.event_engine — triggers and heartbeat."""

import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone, timedelta

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"

import tests._patch_logger  # noqa: F401

import pytest_asyncio
from lib_webbh.database import (
    get_engine, get_session, Base,
    Target, Asset, Location, Parameter, CloudAsset, JobState, Alert,
)

# Patch worker_manager for all event_engine tests
@pytest.fixture(autouse=True)
def mock_wm():
    with patch("orchestrator.event_engine.worker_manager") as wm:
        wm.start_worker = AsyncMock(return_value="fake-cid")
        wm.stop_worker = AsyncMock(return_value=True)
        wm.restart_worker = AsyncMock(return_value=True)
        wm.kill_worker = AsyncMock(return_value=True)
        wm.should_queue = AsyncMock(return_value=False)
        wm.get_container_status = AsyncMock(return_value=None)
        yield wm


@pytest.fixture(autouse=True)
def mock_push():
    with patch("orchestrator.event_engine.push_task", new_callable=AsyncMock) as pt:
        yield pt


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target_with_open_port(db):
    """Target with an asset that has port 443 state='open'."""
    async with get_session() as session:
        t = Target(company_name="WebCorp", base_domain="webcorp.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="ip", asset_value="10.0.0.1", source_tool="nmap")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        loc = Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="open")
        session.add(loc)
        await session.commit()
        return t.id


@pytest_asyncio.fixture
async def seed_target_with_closed_port(db):
    """Target with an asset that has port 443 state='closed'."""
    async with get_session() as session:
        t = Target(company_name="ClosedCorp", base_domain="closed.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="ip", asset_value="10.0.0.2", source_tool="nmap")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        loc = Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="closed")
        session.add(loc)
        await session.commit()
        return t.id


# --- Fix 2: Web trigger must check Location.state ---

@pytest.mark.asyncio
async def test_web_trigger_fires_for_open_port(seed_target_with_open_port, mock_wm):
    from orchestrator.event_engine import _check_web_trigger
    await _check_web_trigger()
    mock_wm.start_worker.assert_called()


@pytest.mark.asyncio
async def test_web_trigger_ignores_closed_port(seed_target_with_closed_port, mock_wm):
    from orchestrator.event_engine import _check_web_trigger
    await _check_web_trigger()
    mock_wm.start_worker.assert_not_called()
