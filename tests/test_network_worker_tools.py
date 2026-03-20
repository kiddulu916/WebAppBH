"""Tests for network_worker tools."""

import os

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_network_worker_concurrency_weight_classes():
    from workers.network_worker.concurrency import WeightClass

    assert WeightClass.LIGHT.value == "light"
    assert WeightClass.MEDIUM.value == "medium"
    assert WeightClass.HEAVY.value == "heavy"


def test_network_worker_concurrency_get_semaphore():
    from workers.network_worker.concurrency import WeightClass, get_semaphore

    for wc in WeightClass:
        sem = get_semaphore(wc)
        assert sem is not None
