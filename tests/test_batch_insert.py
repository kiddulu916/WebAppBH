import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
import asyncio
import tests._patch_logger  # noqa

from lib_webbh.database import get_session, get_engine, Base, Target, Asset
from lib_webbh.batch_insert import BatchInserter

pytestmark = pytest.mark.anyio

@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine

@pytest_asyncio.fixture
async def target(db):
    async with get_session() as session:
        t = Target(company_name="BatchTest", base_domain="batch.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id

async def test_batch_flush_on_size(target):
    inserter = BatchInserter(batch_size=3, flush_interval=60.0)
    for i in range(3):
        await inserter.add(Asset(target_id=target, asset_type="subdomain", asset_value=f"s{i}.batch.com"))
    # Should have auto-flushed at batch_size=3
    assert inserter.pending == 0
    async with get_session() as session:
        from sqlalchemy import select, func
        count = (await session.execute(select(func.count(Asset.id)).where(Asset.target_id == target))).scalar()
        assert count == 3

async def test_manual_flush(target):
    inserter = BatchInserter(batch_size=100, flush_interval=60.0)
    await inserter.add(Asset(target_id=target, asset_type="subdomain", asset_value="manual.batch.com"))
    assert inserter.pending == 1
    total = await inserter.flush()
    assert inserter.pending == 0
    assert total == 1

async def test_empty_flush(db):
    inserter = BatchInserter()
    total = await inserter.flush()
    assert total == 0

async def test_total_flushed_accumulates(target):
    inserter = BatchInserter(batch_size=2, flush_interval=60.0)
    for i in range(5):
        await inserter.add(Asset(target_id=target, asset_type="subdomain", asset_value=f"acc{i}.batch.com"))
    total = await inserter.flush()
    assert total == 5
