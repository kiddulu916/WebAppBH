"""Test AssetSnapshot model creation and querying."""
import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from sqlalchemy import select
from lib_webbh import get_session, Target
from lib_webbh.database import AssetSnapshot, Base, get_engine

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def test_create_asset_snapshot():
    async with get_session() as session:
        target = Target(company_name="DiffCo", base_domain="diff.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        snapshot = AssetSnapshot(
            target_id=target.id,
            scan_number=1,
            asset_count=42,
            asset_hashes={"sub1.diff.com": "abc123", "sub2.diff.com": "def456"},
        )
        session.add(snapshot)
        await session.commit()
        await session.refresh(snapshot)

        assert snapshot.id is not None
        assert snapshot.scan_number == 1
        assert snapshot.asset_count == 42
        assert "sub1.diff.com" in snapshot.asset_hashes
