"""Nuclei template synchronization."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Awaitable

from lib_webbh import setup_logger

logger = setup_logger("template-sync")

TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")
CUSTOM_TEMPLATES_DIR = os.environ.get(
    "CUSTOM_TEMPLATES_DIR", "/app/shared/custom_templates"
)


async def sync_templates(
    run_subprocess: Callable[[list[str], int], Awaitable[str]],
) -> None:
    """Update Nuclei templates and ensure custom template directory exists.

    Parameters
    ----------
    run_subprocess:
        An async callable matching ``VulnScanTool.run_subprocess``
        (accepts ``cmd`` and ``timeout``).
    """
    logger.info("Syncing Nuclei templates to %s", TEMPLATES_DIR)

    try:
        await run_subprocess(
            ["nuclei", "-ut", "-ud", TEMPLATES_DIR],
            timeout=300,
        )
        logger.info("Nuclei template update complete")
    except Exception as exc:
        logger.error("Nuclei template update failed: %s", exc)

    # Ensure custom templates directory exists
    custom_path = Path(CUSTOM_TEMPLATES_DIR)
    custom_path.mkdir(parents=True, exist_ok=True)
    logger.info("Custom templates directory ready: %s", CUSTOM_TEMPLATES_DIR)
