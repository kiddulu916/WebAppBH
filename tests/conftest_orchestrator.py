"""Shared fixtures for orchestrator tests.

Import this module's fixtures via conftest.py or direct import in test files.
"""

import os
import asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Force SQLite for tests before any lib_webbh import
os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

# Patch setup_logger to use a temp directory instead of /app/shared/logs/
# This must happen before any orchestrator module is imported, because
# worker_manager.py and event_engine.py call setup_logger at module level.
import lib_webbh
import lib_webbh.logger

_test_log_dir = tempfile.mkdtemp()
_orig_setup_logger = lib_webbh.logger.setup_logger


def _patched_setup_logger(name, log_dir=_test_log_dir):
    return _orig_setup_logger(name, log_dir=log_dir)


lib_webbh.logger.setup_logger = _patched_setup_logger
lib_webbh.setup_logger = _patched_setup_logger

from lib_webbh.database import get_engine, get_session, Base, Target, Asset, Location, Parameter, CloudAsset, JobState, Alert

# Restore originals after all module-level imports have completed
lib_webbh.logger.setup_logger = _orig_setup_logger
lib_webbh.setup_logger = _orig_setup_logger


@pytest_asyncio.fixture
async def db():
    """Create all tables in a fresh SQLite in-memory DB."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    """Insert a target and return its ID."""
    async with get_session() as session:
        t = Target(company_name="AuditCorp", base_domain="auditcorp.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def mock_docker_client():
    """Return a mocked docker.DockerClient."""
    client = MagicMock()
    client.containers = MagicMock()
    return client


@pytest.fixture
def mock_worker_manager():
    """Patch all worker_manager async functions to no-ops."""
    with patch("orchestrator.event_engine.worker_manager") as wm:
        wm.start_worker = AsyncMock(return_value="fake-container-id")
        wm.stop_worker = AsyncMock(return_value=True)
        wm.restart_worker = AsyncMock(return_value=True)
        wm.pause_worker = AsyncMock(return_value=True)
        wm.unpause_worker = AsyncMock(return_value=True)
        wm.kill_worker = AsyncMock(return_value=True)
        wm.should_queue = AsyncMock(return_value=False)
        wm.get_container_status = AsyncMock(return_value=None)
        yield wm
