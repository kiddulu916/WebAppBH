import os
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from lib_webbh.database import get_engine, get_session, Base


def test_get_engine_returns_async_engine():
    engine = get_engine()
    assert isinstance(engine, AsyncEngine)


def test_get_engine_is_singleton():
    e1 = get_engine()
    e2 = get_engine()
    assert e1 is e2


@pytest.mark.asyncio
async def test_get_session_returns_async_session():
    async with get_session() as session:
        assert isinstance(session, AsyncSession)


@pytest.mark.asyncio
async def test_create_all_tables():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
