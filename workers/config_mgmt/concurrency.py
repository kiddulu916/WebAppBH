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
    "network_config_tester":      WeightClass.LIGHT,
    "admin_interface_finder":     WeightClass.HEAVY,
    "default_credential_tester":  WeightClass.HEAVY,
    "platform_fingerprinter":     WeightClass.LIGHT,
    "file_extension_tester":      WeightClass.LIGHT,
    "backup_file_finder":         WeightClass.LIGHT,
    "FfufTool":                   WeightClass.HEAVY,  # ffuf_tool.py sets name = "FfufTool"
    "api_discovery_tool":         WeightClass.LIGHT,
    "http_method_tester":         WeightClass.LIGHT,
    "hsts_tester":                WeightClass.LIGHT,
    "rpc_tester":                 WeightClass.LIGHT,
    "file_permission_tester":     WeightClass.LIGHT,
    "file_inclusion_tester":      WeightClass.LIGHT,
    "subdomain_takeover_checker": WeightClass.LIGHT,
    "cloud_storage_auditor":      WeightClass.LIGHT,
    "admin_interface_enumerator": WeightClass.HEAVY,
    "admin_param_tamperer":       WeightClass.LIGHT,
    "csp_tester":                 WeightClass.LIGHT,
    "path_confusion_tester":      WeightClass.LIGHT,
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