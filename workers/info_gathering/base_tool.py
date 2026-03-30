# workers/info_gathering/base_tool.py
"""Abstract base class for info gathering tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select

from lib_webbh import (
    Asset,
    Alert,
    Observation,
    Vulnerability,
    get_session,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

logger = setup_logger("info-gathering-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))


class InfoGatheringTool(ABC):
    """Abstract base for all info_gathering tools."""

    worker_type = "info_gathering"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        """Run this tool against the target. Must be implemented by subclasses."""
        ...

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        """Run a command and return stdout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise

        return stdout_bytes.decode("utf-8", errors="replace")

    async def scope_check(self, target_id: int, value: str, scope_manager: ScopeManager) -> bool:
        """Check if a value is in scope before processing."""
        result = scope_manager.is_in_scope(value)
        return result.in_scope

    async def save_asset(self, target_id: int, asset_type: str, asset_value: str,
                         source_tool: str, **extra) -> int | None:
        """Insert an Asset record. Returns asset ID or None if duplicate."""
        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type == asset_type,
                Asset.asset_value == asset_value,
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                return None

            asset = Asset(
                target_id=target_id,
                asset_type=asset_type,
                asset_value=asset_value,
                source_tool=source_tool,
                **extra,
            )
            session.add(asset)
            await session.commit()
            await session.refresh(asset)
            return asset.id

    async def save_observation(self, target_id: int, observation_type: str,
                               data: dict, source_tool: str) -> int:
        """Insert an Observation record. Returns observation ID."""
        async with get_session() as session:
            obs = Observation(
                target_id=target_id,
                observation_type=observation_type,
                data=data,
                source_tool=source_tool,
            )
            session.add(obs)
            await session.commit()
            await session.refresh(obs)
            return obs.id

    async def save_vulnerability(self, target_id: int, **kwargs) -> int:
        """Insert a Vulnerability record. Returns vulnerability ID."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                worker_type=self.worker_type,
                **kwargs,
            )
            session.add(vuln)
            await session.commit()
            await session.refresh(vuln)
            return vuln.id

    async def cooldown_check(self, tool_name: str, target_id: int) -> bool:
        """Check if this tool ran recently against this target."""
        from lib_webbh.database import JobState
        cooldown_hours = int(os.environ.get("COOLDOWN_HOURS", "24"))
        cutoff = datetime.utcnow() - timedelta(hours=cooldown_hours)

        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == self.worker_type,
                JobState.status == "complete",
                JobState.last_tool_executed == tool_name,
                JobState.last_seen >= cutoff,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None