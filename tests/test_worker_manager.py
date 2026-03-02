"""Tests for orchestrator.worker_manager."""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tests._patch_logger  # noqa: F401

from orchestrator.worker_manager import (
    check_resources,
    should_queue,
    ContainerInfo,
    ResourceSnapshot,
)


@pytest.mark.asyncio
async def test_check_resources_returns_snapshot():
    with patch("orchestrator.worker_manager.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 50.0
        mock_mem = MagicMock()
        mock_mem.percent = 60.0
        mock_psutil.virtual_memory.return_value = mock_mem
        snap = await check_resources()
        assert isinstance(snap, ResourceSnapshot)
        assert snap.cpu_percent == 50.0
        assert snap.memory_percent == 60.0
        assert snap.is_healthy is True


@pytest.mark.asyncio
async def test_should_queue_returns_false_when_healthy():
    with patch("orchestrator.worker_manager.check_resources", new_callable=AsyncMock) as mock_cr:
        mock_cr.return_value = ResourceSnapshot(cpu_percent=50.0, memory_percent=60.0, is_healthy=True)
        result = await should_queue()
        assert result is False


@pytest.mark.asyncio
async def test_should_queue_returns_true_when_unhealthy():
    with patch("orchestrator.worker_manager.check_resources", new_callable=AsyncMock) as mock_cr:
        mock_cr.return_value = ResourceSnapshot(cpu_percent=90.0, memory_percent=90.0, is_healthy=False)
        result = await should_queue()
        assert result is True
