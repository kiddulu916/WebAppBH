# tests/test_kill_rerun.py
"""Tests for kill switch, rerun, and clean slate API endpoints."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import (
    Base, Target, Asset, JobState, Vulnerability, Parameter,
    Location, Observation, Identity, CloudAsset, AssetSnapshot,
    Alert, ApiSchema, ScopeViolation, BountySubmission, MobileApp,
    get_engine, get_session,
)


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
async def seed_target(db):
    async with get_session() as session:
        t = Target(
            company_name="KillTest",
            base_domain="killtest.com",
            target_profile={},
            last_playbook="wide_recon",
        )
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.mark.anyio
async def test_target_last_playbook_column(seed_target):
    """Target model has a last_playbook column."""
    async with get_session() as session:
        from sqlalchemy import select
        t = (await session.execute(select(Target).where(Target.id == seed_target))).scalar_one()
        assert t.last_playbook == "wide_recon"
