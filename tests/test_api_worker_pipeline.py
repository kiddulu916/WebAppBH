import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def test_concurrency_semaphore_defaults():
    from workers.api_worker.concurrency import WeightClass, get_semaphores
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 2
    assert light._value >= 1


def test_weight_class_enum():
    from workers.api_worker.concurrency import WeightClass
    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"
