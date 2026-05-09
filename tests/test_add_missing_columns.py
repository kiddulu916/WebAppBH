"""Tests for orchestrator.main._add_missing_columns.

* Verifies the column-sync helper handles the full range of SQLAlchemy
  ``server_default`` argument forms:

    1. Plain ``str`` (e.g. ``server_default="pending"``)
    2. ``text(...)`` clause (TextClause – exposes ``.text``)
    3. SQL function expression (e.g. ``func.now()`` – a ClauseElement
       without a ``.text`` attribute)

! Regression test: the original implementation blindly accessed
  ``col.server_default.arg.text`` and crashed with
  ``AttributeError: 'str' object has no attribute 'text'`` whenever the
  argument was anything other than a TextClause.
"""

from __future__ import annotations

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
import tests._patch_logger  # noqa: F401 — must precede orchestrator imports

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    func,
    inspect,
    text,
)
from sqlalchemy.ext.asyncio import create_async_engine

from orchestrator.main import _add_missing_columns


def _build_existing_table(md: MetaData) -> Table:
    # * Minimal baseline table that already exists in the DB.
    return Table(
        "tdd_widgets",
        md,
        Column("id", Integer, primary_key=True, autoincrement=True),
    )


def _build_full_table(md: MetaData) -> Table:
    # * Full ORM definition — extra columns must be ALTER-added by the helper.
    return Table(
        "tdd_widgets",
        md,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column(
            "status",
            String(20),
            nullable=False,
            server_default="pending",
        ),
        Column(
            "label",
            String(20),
            nullable=False,
            server_default=text("'archived'"),
        ),
        Column(
            "created_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
        Column(
            "is_active",
            Boolean,
            nullable=False,
            default=True,
        ),
    )


@pytest_asyncio.fixture
async def sqlite_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_add_missing_columns_handles_all_server_default_forms(sqlite_engine):
    """The helper must add every missing column without crashing.

    Reproduces the production crash:

        File "/app/orchestrator/main.py", line 240, in _add_missing_columns
            default_clause = f" DEFAULT {col.server_default.arg.text}"
        AttributeError: 'str' object has no attribute 'text'
    """
    # * Step 1 — create only the baseline schema in the DB.
    baseline_md = MetaData()
    _build_existing_table(baseline_md)
    async with sqlite_engine.begin() as conn:
        await conn.run_sync(baseline_md.create_all)

    # * Step 2 — define the "real" ORM metadata with extra columns.
    full_md = MetaData()
    _build_full_table(full_md)

    # * Step 3 — sync. Must not raise.
    async with sqlite_engine.begin() as conn:
        await conn.run_sync(_add_missing_columns, full_md)

    # * Step 4 — verify every expected column now exists.
    async with sqlite_engine.connect() as conn:
        cols = await conn.run_sync(
            lambda c: {col["name"] for col in inspect(c).get_columns("tdd_widgets")}
        )
    assert {"id", "status", "label", "created_at", "is_active"}.issubset(cols)


@pytest.mark.asyncio
async def test_add_missing_columns_string_server_default_is_quoted(sqlite_engine):
    """Plain-string ``server_default`` must be rendered as a SQL string literal.

    SQLAlchemy itself renders ``server_default="pending"`` as
    ``DEFAULT 'pending'`` via ``render_literal_value``. The helper must
    behave identically so existing rows pick up the documented default.
    """
    baseline_md = MetaData()
    Table(
        "tdd_status_only",
        baseline_md,
        Column("id", Integer, primary_key=True, autoincrement=True),
    )
    async with sqlite_engine.begin() as conn:
        await conn.run_sync(baseline_md.create_all)

    full_md = MetaData()
    Table(
        "tdd_status_only",
        full_md,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("status", String(20), nullable=False, server_default="pending"),
    )

    async with sqlite_engine.begin() as conn:
        await conn.run_sync(_add_missing_columns, full_md)
        # Inserting without an explicit status should pick up the default.
        await conn.execute(text("INSERT INTO tdd_status_only DEFAULT VALUES"))

    async with sqlite_engine.connect() as conn:
        result = await conn.execute(text("SELECT status FROM tdd_status_only"))
        rows = result.fetchall()

    assert rows == [("pending",)]


@pytest.mark.asyncio
async def test_add_missing_columns_noop_when_db_is_in_sync(sqlite_engine):
    """When the DB already has every column, the helper must be a no-op."""
    md = MetaData()
    _build_full_table(md)
    async with sqlite_engine.begin() as conn:
        await conn.run_sync(md.create_all)

    # Calling again with the same metadata must not raise or alter anything.
    async with sqlite_engine.begin() as conn:
        await conn.run_sync(_add_missing_columns, md)
