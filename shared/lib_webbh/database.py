"""Async database engine singleton, session factory, and declarative base."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from sqlalchemy import func
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


# ---------------------------------------------------------------------------
# URL builder (private)
# ---------------------------------------------------------------------------
def _build_url() -> str:
    """Construct a database URL from environment variables.

    Environment variables
    ---------------------
    DB_DRIVER : str  – SQLAlchemy async driver (default ``postgresql+asyncpg``)
    DB_USER   : str  – database user           (default ``webbh_admin``)
    DB_PASS   : str  – database password        (default ``""``)
    DB_HOST   : str  – database host            (default ``localhost``)
    DB_PORT   : str  – database port            (default ``5432``)
    DB_NAME   : str  – database / file name     (default ``webbh``)
    """
    driver = os.environ.get("DB_DRIVER", "postgresql+asyncpg")
    name = os.environ.get("DB_NAME", "webbh")

    if driver.startswith("sqlite"):
        return f"{driver}:///{name}"

    user = os.environ.get("DB_USER", "webbh_admin")
    password = os.environ.get("DB_PASS", "")
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    return f"{driver}://{user}:{password}@{host}:{port}/{name}"


# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------
def get_engine() -> AsyncEngine:
    """Return the global :class:`AsyncEngine`, creating it on first call."""
    global _engine
    if _engine is None:
        url = _build_url()
        kwargs: dict = {}
        if not url.startswith("sqlite"):
            kwargs.update(
                pool_size=10,
                max_overflow=20,
                pool_recycle=3600,
            )
        _engine = create_async_engine(url, **kwargs)
    return _engine


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------
@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield an :class:`AsyncSession` and close it on exit.

    Usage::

        async with get_session() as session:
            result = await session.execute(...)
    """
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
        )

    session = _session_factory()
    try:
        yield session
    finally:
        await session.close()


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------
class Base(AsyncAttrs, DeclarativeBase):
    """Project-wide declarative base with async attribute support."""


# ---------------------------------------------------------------------------
# Timestamp mixin
# ---------------------------------------------------------------------------
class TimestampMixin:
    """Mixin that adds ``created_at`` / ``updated_at`` UTC timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        default=func.now(),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(),
        server_default=func.now(),
        onupdate=func.now(),
    )
