"""Abstract base class for fuzzing tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from sqlalchemy import select, distinct

from lib_webbh import (
    Alert,
    Asset,
    JobState,
    Location,
    Parameter,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.fuzzing_worker.concurrency import WeightClass

logger = setup_logger("fuzzing-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))


class FuzzingTool(ABC):
    """Base class for all fuzzing tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class
    attributes and implement ``execute()``.
    """

    name: str
    weight_class: WeightClass

    # ------------------------------------------------------------------
    # Abstract method
    # ------------------------------------------------------------------

    @abstractmethod
    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run the tool against *target* and return a stats dict."""

    # ------------------------------------------------------------------
    # Cooldown helpers
    # ------------------------------------------------------------------

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        """Return True if this tool was completed within COOLDOWN_HOURS."""
        cutoff = datetime.utcnow() - timedelta(hours=COOLDOWN_HOURS)
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
                JobState.status == "COMPLETED",
                JobState.last_tool_executed == self.name,
                JobState.last_seen >= cutoff,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None

    async def update_tool_state(self, target_id: int, container_name: str) -> None:
        """Update JobState.last_tool_executed and last_seen for this tool."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.last_tool_executed = self.name
                job.last_seen = datetime.utcnow()
                await session.commit()

    # ------------------------------------------------------------------
    # Subprocess runner
    # ------------------------------------------------------------------

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        """Run a command and return decoded stdout."""
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

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    async def _get_live_urls(self, target_id: int) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets with open HTTP(S) ports.

        Joins Asset -> Location where port in (80, 443) and state='open',
        returning DISTINCT pairs.
        """
        async with get_session() as session:
            stmt = (
                select(distinct(Asset.id), Asset.asset_value)
                .join(Location, Location.asset_id == Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Location.port.in_([80, 443]),
                    Location.state == "open",
                )
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    async def _get_all_url_assets(self, target_id: int) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for all assets with asset_type='url'."""
        async with get_session() as session:
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "url",
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _save_asset(
        self,
        target_id: int,
        url: str,
        scope_manager: ScopeManager,
        source_tool: str | None = None,
    ) -> int | None:
        """Scope-check and upsert an Asset row. Returns asset id or None."""
        scope_result = scope_manager.is_in_scope(url)
        if not scope_result.in_scope:
            return None

        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type == scope_result.asset_type,
                Asset.asset_value == scope_result.normalized,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing is not None:
                return existing.id

            asset = Asset(
                target_id=target_id,
                asset_type=scope_result.asset_type,
                asset_value=scope_result.normalized,
                source_tool=source_tool or self.name,
            )
            session.add(asset)
            await session.commit()
            return asset.id

    async def _save_parameter(
        self,
        asset_id: int,
        param_name: str,
        param_value: str | None,
        source_url: str | None,
    ) -> bool:
        """Dedup-insert a Parameter row. Returns True if newly inserted."""
        async with get_session() as session:
            stmt = select(Parameter).where(
                Parameter.asset_id == asset_id,
                Parameter.param_name == param_name,
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                return False

            param = Parameter(
                asset_id=asset_id,
                param_name=param_name,
                param_value=param_value,
                source_url=source_url,
            )
            session.add(param)
            await session.commit()
            return True

    async def _save_vulnerability(
        self,
        target_id: int,
        asset_id: int,
        severity: str,
        title: str,
        description: str,
        poc: str | None = None,
    ) -> int:
        """Insert a Vulnerability row and create an Alert for critical/high."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity=severity,
                title=title,
                description=description,
                poc=poc,
                source_tool=self.name,
            )
            session.add(vuln)
            await session.flush()
            vuln_id = vuln.id
            await session.commit()

        if severity in ("critical", "high"):
            await self._create_alert(
                target_id,
                vuln_id,
                f"[{severity.upper()}] {title}",
            )

        return vuln_id

    # ------------------------------------------------------------------
    # Alerting
    # ------------------------------------------------------------------

    async def _create_alert(
        self,
        target_id: int,
        vuln_id: int,
        message: str,
    ) -> None:
        """Write alert to DB and push to Redis for SSE."""
        logger.warning(f"ALERT: {message}")
        async with get_session() as session:
            alert = Alert(
                target_id=target_id,
                vulnerability_id=vuln_id,
                alert_type="critical",
                message=message,
            )
            session.add(alert)
            await session.commit()
            alert_id = alert.id

        await push_task(f"events:{target_id}", {
            "event": "CRITICAL_ALERT",
            "alert_id": alert_id,
            "vulnerability_id": vuln_id,
            "message": message,
        })
