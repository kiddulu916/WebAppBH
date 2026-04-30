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


async def test_failed_flush_restores_rows_for_retry(target):
    """If commit fails, the in-flight batch must be returned to the buffer."""
    from unittest.mock import patch, AsyncMock, MagicMock

    inserter = BatchInserter(batch_size=100, flush_interval=60.0)
    items = [
        Asset(target_id=target, asset_type="subdomain", asset_value=f"retry{i}.batch.com")
        for i in range(3)
    ]
    for item in items:
        await inserter.add(item)
    assert inserter.pending == 3

    # First flush attempt: simulate a transient DB failure inside the session.
    fake_session = MagicMock()
    fake_session.add_all = MagicMock()
    fake_session.commit = AsyncMock(side_effect=RuntimeError("db unavailable"))
    fake_session.rollback = AsyncMock()

    class _FakeCtx:
        async def __aenter__(self):
            return fake_session

        async def __aexit__(self, exc_type, exc, tb):
            return False

    with patch("lib_webbh.batch_insert.get_session", return_value=_FakeCtx()):
        with pytest.raises(RuntimeError):
            await inserter.flush()

    assert inserter.pending == 3, "Failed batch must be restored to the buffer"
    fake_session.rollback.assert_awaited()

    # Retry without the patch — should succeed against the real session.
    total = await inserter.flush()
    assert total == 3
    assert inserter.pending == 0
