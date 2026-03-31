"""Semaphore pools for heavy and light config management tools."""

import asyncio
import os
from enum import Enum

_heavy: asyncio.BoundedSemaphore | None = None
_light: asyncio.BoundedSemaphore | None = None


class WeightClass(Enum):
    HEAVY = "heavy"
    LIGHT = "light"


# Tool weight configuration
TOOL_WEIGHTS = {
    "Nmap": WeightClass.HEAVY,
    "NetworkConfigAuditor": WeightClass.LIGHT,
    "PlatformAuditor": WeightClass.LIGHT,
    "ExtensionProber": WeightClass.LIGHT,
    "FfufTool": WeightClass.HEAVY,
    "BackupScanner": WeightClass.LIGHT,
    "AdminFinder": WeightClass.LIGHT,
    "DefaultCredChecker": WeightClass.LIGHT,
    "MethodTester": WeightClass.LIGHT,
    "HstsAuditor": WeightClass.LIGHT,
    "CrossDomainPolicyParser": WeightClass.LIGHT,
    "PermissionProber": WeightClass.LIGHT,
    "SubjackTool": WeightClass.LIGHT,
    "CnameChecker": WeightClass.LIGHT,
    "BucketFinder": WeightClass.LIGHT,
    "S3Scanner": WeightClass.LIGHT,
    "AzureBlobProber": WeightClass.LIGHT,
    "GcpBucketProber": WeightClass.LIGHT,
    "TrufflehogTool": WeightClass.HEAVY,
}


def get_semaphores(
    force_new: bool = False,
) -> tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
    """Return (heavy, light) semaphore pair.

    Reads HEAVY_CONCURRENCY and LIGHT_CONCURRENCY from env.
    Defaults: heavy=2, light=cpu_count().
    """
    global _heavy, _light
    if _heavy is None or _light is None or force_new:
        heavy_cap = int(os.environ.get("HEAVY_CONCURRENCY", "2"))
        light_cap = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))
        _heavy = asyncio.BoundedSemaphore(heavy_cap)
        _light = asyncio.BoundedSemaphore(light_cap)
    return _heavy, _light


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    """Return the semaphore for the given weight class."""
    heavy, light = get_semaphores()
    return heavy if weight is WeightClass.HEAVY else light


def get_tool_weight(tool_name: str) -> WeightClass:
    """Return the weight class for a given tool name."""
    return TOOL_WEIGHTS.get(tool_name, WeightClass.LIGHT)