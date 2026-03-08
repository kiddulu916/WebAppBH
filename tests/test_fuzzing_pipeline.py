import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_concurrency_semaphore_defaults():
    from workers.fuzzing_worker.concurrency import WeightClass, get_semaphores
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 2
    assert light._value >= 1


# ---------------------------------------------------------------------------
# FuzzingTool base class tests
# ---------------------------------------------------------------------------

async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _make_dummy_tool():
    from workers.fuzzing_worker.base_tool import FuzzingTool
    from workers.fuzzing_worker.concurrency import WeightClass

    class DummyFuzzTool(FuzzingTool):
        name = "dummy-fuzz"
        weight_class = WeightClass.LIGHT

        async def execute(self, target, scope_manager, target_id, container_name,
                          headers=None, **kwargs):
            return {"found": 0, "in_scope": 0, "new": 0}

    return DummyFuzzTool()


@pytest.mark.anyio
async def test_fuzzing_base_tool_check_cooldown_no_job():
    await _create_tables()
    tool = _make_dummy_tool()
    result = await tool.check_cooldown(999, "test-container")
    assert result is False


@pytest.mark.anyio
async def test_fuzzing_base_tool_save_asset_out_of_scope():
    await _create_tables()
    from lib_webbh import Target, get_session
    from lib_webbh.scope import ScopeManager

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com",
                   target_profile={"in_scope_domains": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        target_id = t.id

    tool = _make_dummy_tool()
    scope = ScopeManager({"in_scope_domains": ["*.acme.com"]})
    result = await tool._save_asset(target_id, "http://evil.com/test", scope)
    assert result is None


@pytest.mark.anyio
async def test_fuzzing_base_tool_save_parameter_dedup():
    await _create_tables()
    from lib_webbh import Asset, Target, get_session

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a = Asset(target_id=t.id, asset_type="url",
                  asset_value="https://acme.com/api", source_tool="test")
        session.add(a)
        await session.commit()
        asset_id = a.id

    tool = _make_dummy_tool()
    first = await tool._save_parameter(asset_id, "debug", "", "https://acme.com/api")
    second = await tool._save_parameter(asset_id, "debug", "", "https://acme.com/api")
    assert first is True
    assert second is False


@pytest.mark.anyio
async def test_fuzzing_base_tool_save_vulnerability_creates_alert():
    await _create_tables()
    from lib_webbh import Alert, Asset, Target, get_session
    from sqlalchemy import select

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a = Asset(target_id=t.id, asset_type="url",
                  asset_value="https://acme.com/.env", source_tool="test")
        session.add(a)
        await session.commit()
        target_id, asset_id = t.id, a.id

    tool = _make_dummy_tool()
    with patch("workers.fuzzing_worker.base_tool.push_task", new_callable=AsyncMock):
        vuln_id = await tool._save_vulnerability(
            target_id, asset_id, "critical",
            "Exposed .env file", "Environment file publicly accessible",
        )

    assert vuln_id is not None
    async with get_session() as session:
        alerts = (await session.execute(
            select(Alert).where(Alert.target_id == target_id)
        )).scalars().all()
        assert len(alerts) == 1
