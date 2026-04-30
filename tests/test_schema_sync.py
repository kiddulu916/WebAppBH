"""Verifies orchestrator schema-sync DDL is idempotent and safe to retry.

The orchestrator runs ``_add_missing_columns`` on every startup. If a
ROLLBACK is forced mid-migration the live DB must remain in a usable
state and the next startup must complete without raising.
"""
from __future__ import annotations

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
import tests._patch_logger  # noqa: F401

from sqlalchemy import inspect, text

from lib_webbh.database import Base, get_engine

# Import the schema-sync helper without pulling in FastAPI / orchestrator deps.
pytest.importorskip("fastapi")
pytest.importorskip("psutil")
from orchestrator.main import _add_missing_columns  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest_asyncio.fixture
async def db_engine():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


async def test_schema_sync_is_idempotent(db_engine):
    """Running _add_missing_columns twice on a fully synced schema must be a no-op."""
    async with db_engine.begin() as conn:
        await conn.run_sync(_add_missing_columns)
        await conn.run_sync(_add_missing_columns)


async def test_schema_sync_recovers_after_rollback(db_engine):
    """If the previous migration transaction was rolled back, the next call still succeeds."""
    # Drop a column to simulate an out-of-sync DB, then re-add it.
    async with db_engine.begin() as conn:
        # SQLite supports ALTER TABLE ... DROP COLUMN from 3.35+; if not available,
        # the test should still pass because the schema is already in sync.
        try:
            await conn.execute(text("ALTER TABLE targets DROP COLUMN priority"))
        except Exception:
            pytest.skip("SQLite build does not support DROP COLUMN")

    # Force a rollback mid-migration to simulate a failed deploy.
    async with db_engine.connect() as conn:
        trans = await conn.begin()
        await conn.run_sync(_add_missing_columns)
        await trans.rollback()

    # Next startup attempt must succeed and the column must be present.
    async with db_engine.begin() as conn:
        await conn.run_sync(_add_missing_columns)

    async with db_engine.connect() as conn:
        def _columns(sync_conn) -> set[str]:
            inspector = inspect(sync_conn)
            return {c["name"] for c in inspector.get_columns("targets")}

        cols = await conn.run_sync(_columns)
        assert "priority" in cols
