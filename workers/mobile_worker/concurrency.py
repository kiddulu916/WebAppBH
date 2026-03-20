"""Semaphore pools for static and dynamic mobile-worker tools."""

import asyncio
import os
from enum import Enum

_static: asyncio.BoundedSemaphore | None = None
_dynamic: asyncio.BoundedSemaphore | None = None


class WeightClass(Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


def get_semaphores(
    force_new: bool = False,
) -> tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
    """Return (static, dynamic) semaphore pair.

    Reads MOBILE_STATIC_CONCURRENCY and MOBILE_DYNAMIC_CONCURRENCY from env.
    Defaults: static=3, dynamic=1.
    """
    global _static, _dynamic
    if _static is None or _dynamic is None or force_new:
        static_cap = int(os.environ.get("MOBILE_STATIC_CONCURRENCY", "3"))
        dynamic_cap = int(os.environ.get("MOBILE_DYNAMIC_CONCURRENCY", "1"))
        _static = asyncio.BoundedSemaphore(static_cap)
        _dynamic = asyncio.BoundedSemaphore(dynamic_cap)
    return _static, _dynamic


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    """Return the semaphore for the given weight class."""
    static, dynamic = get_semaphores()
    return static if weight is WeightClass.STATIC else dynamic
