"""Tests for session management concurrency module."""
import asyncio
import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_weight_class_enum_values():
    from workers.session_mgmt.concurrency import WeightClass

    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


def test_get_semaphores_returns_bounded_semaphores():
    from workers.session_mgmt.concurrency import get_semaphores

    heavy, light = get_semaphores(force_new=True)
    assert isinstance(heavy, asyncio.BoundedSemaphore)
    assert isinstance(light, asyncio.BoundedSemaphore)


def test_get_semaphore_returns_heavy():
    from workers.session_mgmt.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.HEAVY)
    assert isinstance(sem, asyncio.BoundedSemaphore)


def test_get_semaphore_returns_light():
    from workers.session_mgmt.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.LIGHT)
    assert isinstance(sem, asyncio.BoundedSemaphore)


def test_semaphores_respect_env_vars():
    from workers.session_mgmt.concurrency import get_semaphores

    os.environ["HEAVY_CONCURRENCY"] = "3"
    os.environ["LIGHT_CONCURRENCY"] = "8"
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 3
    assert light._value == 8
    del os.environ["HEAVY_CONCURRENCY"]
    del os.environ["LIGHT_CONCURRENCY"]
