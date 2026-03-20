"""Tests for cloud_worker tools."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_cloud_worker_concurrency_weight_classes():
    from workers.cloud_worker.concurrency import WeightClass

    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


def test_cloud_worker_concurrency_get_semaphore():
    from workers.cloud_worker.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.HEAVY)
    assert sem is not None
