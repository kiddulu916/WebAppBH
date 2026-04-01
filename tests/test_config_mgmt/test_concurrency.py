"""Tests for config management concurrency module."""
import asyncio
import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_weight_class_enum_values():
    from workers.config_mgmt.concurrency import WeightClass

    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


def test_get_semaphores_returns_bounded_semaphores():
    from workers.config_mgmt.concurrency import get_semaphores

    heavy, light = get_semaphores(force_new=True)
    assert isinstance(heavy, asyncio.BoundedSemaphore)
    assert isinstance(light, asyncio.BoundedSemaphore)


def test_get_semaphore_returns_heavy():
    from workers.config_mgmt.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.HEAVY)
    assert isinstance(sem, asyncio.BoundedSemaphore)


def test_get_semaphore_returns_light():
    from workers.config_mgmt.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.LIGHT)
    assert isinstance(sem, asyncio.BoundedSemaphore)


def test_semaphores_respect_env_vars():
    from workers.config_mgmt.concurrency import get_semaphores

    os.environ["HEAVY_CONCURRENCY"] = "5"
    os.environ["LIGHT_CONCURRENCY"] = "10"
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 5
    assert light._value == 10
    del os.environ["HEAVY_CONCURRENCY"]
    del os.environ["LIGHT_CONCURRENCY"]


def test_tool_weights_defined():
    from workers.config_mgmt.concurrency import TOOL_WEIGHTS, WeightClass

    assert "Nmap" in TOOL_WEIGHTS
    assert TOOL_WEIGHTS["Nmap"] == WeightClass.HEAVY
    assert "NetworkConfigAuditor" in TOOL_WEIGHTS
    assert TOOL_WEIGHTS["NetworkConfigAuditor"] == WeightClass.LIGHT


def test_get_tool_weight():
    from workers.config_mgmt.concurrency import get_tool_weight, WeightClass

    assert get_tool_weight("Nmap") == WeightClass.HEAVY
    assert get_tool_weight("NetworkConfigAuditor") == WeightClass.LIGHT
    assert get_tool_weight("unknown_tool") == WeightClass.LIGHT
