# tests/test_chain_worker_concurrency.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.concurrency import WeightClass, get_semaphore


def test_weight_class_values():
    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.MEDIUM.value == "medium"
    assert WeightClass.LIGHT.value == "light"


@pytest.mark.anyio
async def test_heavy_semaphore_acquires():
    sem = get_semaphore(WeightClass.HEAVY)
    async with sem:
        pass


@pytest.mark.anyio
async def test_light_semaphore_allows_concurrency():
    import asyncio
    sem = get_semaphore(WeightClass.LIGHT)
    acquired = 0

    async def acquire():
        nonlocal acquired
        async with sem:
            acquired += 1
            await asyncio.sleep(0.01)

    await asyncio.gather(*[acquire() for _ in range(4)])
    assert acquired == 4
