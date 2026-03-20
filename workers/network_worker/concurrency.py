"""Semaphore pools for network-worker tools."""

import asyncio
import os
from enum import Enum

_heavy: asyncio.BoundedSemaphore | None = None
_medium: asyncio.BoundedSemaphore | None = None
_light: asyncio.BoundedSemaphore | None = None


class WeightClass(Enum):
    HEAVY = "heavy"
    MEDIUM = "medium"
    LIGHT = "light"


def get_semaphores(
    force_new: bool = False,
) -> tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
    """Return (heavy, medium, light) semaphore tuple.

    Reads HEAVY_CONCURRENCY, MEDIUM_CONCURRENCY, LIGHT_CONCURRENCY from env.
    Defaults: heavy=1, medium=2, light=4.
    """
    global _heavy, _medium, _light
    if _heavy is None or _medium is None or _light is None or force_new:
        heavy_cap = int(os.environ.get("HEAVY_CONCURRENCY", "1"))
        medium_cap = int(os.environ.get("MEDIUM_CONCURRENCY", "2"))
        light_cap = int(os.environ.get("LIGHT_CONCURRENCY", "4"))
        _heavy = asyncio.BoundedSemaphore(heavy_cap)
        _medium = asyncio.BoundedSemaphore(medium_cap)
        _light = asyncio.BoundedSemaphore(light_cap)
    return _heavy, _medium, _light


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    """Return the semaphore for the given weight class."""
    heavy, medium, light = get_semaphores()
    if weight is WeightClass.HEAVY:
        return heavy
    if weight is WeightClass.MEDIUM:
        return medium
    return light
