"""Integration: run a tool with mocked subprocess, verify scope + DB inserts."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"

from lib_webbh import Base, get_engine, get_session, Target, Asset, JobState
from sqlalchemy import select


@pytest.fixture
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def seed_target(setup_db):
    async with get_session() as session:
        target = Target(
            company_name="TestCorp",
            base_domain="example.com",
            target_profile={
                "in_scope_domains": ["*.example.com"],
                "out_scope_domains": [],
                "in_scope_cidrs": [],
                "in_scope_regex": [],
            },
        )
        session.add(target)
        await session.commit()
        return target.id


@pytest.mark.anyio
async def test_subfinder_inserts_in_scope_assets_only(seed_target):
    target_id = seed_target

    async with get_session() as session:
        result = await session.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one()

    # Create job_state
    async with get_session() as session:
        job = JobState(
            target_id=target_id,
            container_name="test-recon",
            current_phase="init",
            status="RUNNING",
        )
        session.add(job)
        await session.commit()

    subfinder_output = "api.example.com\nwww.example.com\noutofscope.evil.com\n"

    async def mock_subprocess(*cmd, **kwargs):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(subfinder_output.encode(), b"")
        )
        return mock_proc

    from lib_webbh.scope import ScopeManager
    from workers.recon_core.tools.subfinder import Subfinder

    scope_mgr = ScopeManager(target.target_profile)
    tool = Subfinder()

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
        stats = await tool.execute(
            target=target,
            scope_manager=scope_mgr,
            target_id=target_id,
            container_name="test-recon",
        )

    assert stats["found"] == 3
    assert stats["in_scope"] == 2
    assert stats["new"] == 2

    async with get_session() as session:
        result = await session.execute(
            select(Asset).where(Asset.target_id == target_id)
        )
        assets = result.scalars().all()
        values = {a.asset_value for a in assets}

    assert "api.example.com" in values
    assert "www.example.com" in values
    assert "outofscope.evil.com" not in values
