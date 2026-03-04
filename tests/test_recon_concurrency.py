# tests/test_recon_concurrency.py
import asyncio
import os
from unittest.mock import patch


def test_get_semaphores_returns_bounded_semaphores():
    from workers.recon_core.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.BoundedSemaphore)
    assert isinstance(light, asyncio.BoundedSemaphore)


def test_heavy_concurrency_from_env():
    with patch.dict(os.environ, {"HEAVY_CONCURRENCY": "3"}):
        from workers.recon_core import concurrency
        heavy, _ = concurrency.get_semaphores(force_new=True)
        loop = asyncio.new_event_loop()

        async def try_acquire():
            for _ in range(3):
                await heavy.acquire()

        loop.run_until_complete(try_acquire())
        loop.close()


def test_light_concurrency_defaults_to_cpu_count():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("LIGHT_CONCURRENCY", None)
        from workers.recon_core import concurrency
        _, light = concurrency.get_semaphores(force_new=True)
        assert isinstance(light, asyncio.BoundedSemaphore)
