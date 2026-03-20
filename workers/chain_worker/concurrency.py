# workers/chain_worker/concurrency.py
from __future__ import annotations
import asyncio
import os
from enum import Enum

_semaphores: dict[str, asyncio.BoundedSemaphore] = {}

class WeightClass(Enum):
    HEAVY = "heavy"
    MEDIUM = "medium"
    LIGHT = "light"

_DEFAULTS = {WeightClass.HEAVY: 1, WeightClass.MEDIUM: 2, WeightClass.LIGHT: 4}
_ENV_KEYS = {WeightClass.HEAVY: "HEAVY_CONCURRENCY", WeightClass.MEDIUM: "MEDIUM_CONCURRENCY", WeightClass.LIGHT: "LIGHT_CONCURRENCY"}

def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    if weight.value not in _semaphores:
        cap = int(os.environ.get(_ENV_KEYS[weight], _DEFAULTS[weight]))
        _semaphores[weight.value] = asyncio.BoundedSemaphore(cap)
    return _semaphores[weight.value]
