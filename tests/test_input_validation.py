# tests/test_input_validation.py
"""Tests for Pydantic input validation constraints on orchestrator models."""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from lib_webbh.database import get_engine, Base

# Patch event_engine background tasks before importing app
with patch("orchestrator.event_engine.EventEngine") as MockEventEngine:
    mock_engine_instance = MagicMock()
    mock_engine_instance.run = AsyncMock()
    MockEventEngine.return_value = mock_engine_instance
    from orchestrator.main import app


API_KEY_HEADER = {"X-API-KEY": "test-api-key-1234"}


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# --- TargetCreate validation ---

@pytest.mark.asyncio
async def test_target_create_empty_company(db, client):
    """company_name='' should be rejected (min_length=1)."""
    resp = await client.post(
        "/api/v1/targets",
        json={"company_name": "", "base_domain": "example.com"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_target_create_empty_domain(db, client):
    """base_domain='' should be rejected (min_length=3)."""
    resp = await client.post(
        "/api/v1/targets",
        json={"company_name": "TestCorp", "base_domain": ""},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 422


# --- BountyCreate validation ---

@pytest.mark.asyncio
async def test_bounty_negative_payout(db, client):
    """expected_payout=-1 should be rejected (ge=0)."""
    resp = await client.post(
        "/api/v1/bounties",
        json={
            "target_id": 1,
            "vulnerability_id": 1,
            "platform": "hackerone",
            "expected_payout": -1,
        },
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 422


# --- ScheduleCreate validation ---

@pytest.mark.asyncio
async def test_schedule_short_cron(db, client):
    """cron_expression='x' should be rejected (min_length=5)."""
    resp = await client.post(
        "/api/v1/schedules",
        json={"target_id": 1, "cron_expression": "x"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 422


# --- PlaybookCreate validation ---

@pytest.mark.asyncio
async def test_playbook_empty_name(db, client):
    """name='' should be rejected (min_length=1)."""
    resp = await client.post(
        "/api/v1/playbooks",
        json={"name": "", "stages": [{"tools": ["nmap"]}]},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_playbook_empty_stages(db, client):
    """stages=[] should be rejected (min_length=1)."""
    resp = await client.post(
        "/api/v1/playbooks",
        json={"name": "my_playbook", "stages": []},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 422
