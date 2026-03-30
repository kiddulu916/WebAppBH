# tests/test_resource_guard.py
import pytest
from unittest.mock import patch, AsyncMock

pytestmark = pytest.mark.anyio


def test_get_batch_config_green():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("green")
    assert "critical" in config["queues"]
    assert "low" in config["queues"]
    assert config["batch_multiplier"] == 1.0
    assert config["delay_seconds"] == 0


def test_get_batch_config_yellow():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("yellow")
    assert "low" not in config["queues"]
    assert config["batch_multiplier"] == 0.5


def test_get_batch_config_red():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("red")
    assert set(config["queues"]) == {"critical", "high"}
    assert config["delay_seconds"] == 5


def test_get_batch_config_critical():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("critical")
    assert config["queues"] == []
    assert config["batch_multiplier"] == 0


def test_manual_override():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    guard.set_override("red")
    # Override should return the overridden tier
    assert guard._override == "red"

    guard.clear_override()
    assert guard._override is None


async def test_get_tier_with_override():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    guard.set_override("critical")
    tier = await guard.get_current_tier()
    assert tier == "critical"