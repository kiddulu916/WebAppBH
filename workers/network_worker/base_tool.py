"""Abstract base class for network testing tool wrappers."""

from __future__ import annotations

import asyncio
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta

from sqlalchemy import select

from lib_webbh import (
    Alert,
    Asset,
    Identity,
    JobState,
    Location,
    Observation,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.network_worker.concurrency import WeightClass

logger = setup_logger("network-test-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# Ports typically served by HTTP — excluded from network worker scope
HTTP_PORTS = {80, 443, 8080, 8443}


class NetworkTestTool(ABC):
    """Base class for all network testing tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class
    attributes and implement ``execute()``.
    """

    name: str
    weight_class: WeightClass

    @abstractmethod
    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        """Run the tool and return a stats dict."""

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
    # Cooldown helpers
    # ------------------------------------------------------------------

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        """Return True if this tool was completed within COOLDOWN_HOURS."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=COOLDOWN_HOURS)
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
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _load_oos_attacks_sync(self, profile_path: str) -> list[str]:
        """Read oos_attacks list from profile JSON. Returns [] on error."""
        try:
            with open(profile_path, "r") as f:
                data = json.load(f)
            return data.get("oos_attacks", [])
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return []

    async def _load_oos_attacks(self, target_id: int) -> list[str]:
        """Load oos_attacks from shared/config/{target_id}/profile.json."""
        config_dir = os.environ.get("CONFIG_DIR", "shared/config")
        profile_path = os.path.join(config_dir, str(target_id), "profile.json")
        return self._load_oos_attacks_sync(profile_path)

    async def _get_non_http_locations(self, target_id: int) -> list[Location]:
        """Fetch Location rows for non-HTTP ports."""
        async with get_session() as session:
            stmt = select(Location).join(Asset).where(
                Asset.target_id == target_id,
                Location.state == "open",
                Location.port.notin_(HTTP_PORTS),
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_locations_by_service(
        self, target_id: int, service_names: list[str]
    ) -> list[Location]:
        """Fetch Location rows matching specific service names."""
        from sqlalchemy import func

        async with get_session() as session:
            stmt = select(Location).join(Asset).where(
                Asset.target_id == target_id,
                Location.state == "open",
                func.lower(Location.service).in_([s.lower() for s in service_names]),
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _save_location(
        self,
        asset_id: int,
        port: int,
        protocol: str = "tcp",
        service: str | None = None,
        state: str = "open",
    ) -> int:
        """Upsert a Location row. Returns location id."""
        async with get_session() as session:
            stmt = select(Location).where(
                Location.asset_id == asset_id,
                Location.port == port,
                Location.protocol == protocol,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                if service:
                    existing.service = service
                existing.state = state
                await session.commit()
                return existing.id

            loc = Location(
                asset_id=asset_id,
                port=port,
                protocol=protocol,
                service=service,
                state=state,
            )
            session.add(loc)
            await session.flush()
            loc_id = loc.id
            await session.commit()
            return loc_id

    async def _save_observation_tech_stack(
        self,
        asset_id: int,
        tech_data: dict,
    ) -> int:
        """Upsert tech_stack JSON on the Observation for an asset."""
        async with get_session() as session:
            stmt = select(Observation).where(Observation.asset_id == asset_id)
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                merged = existing.tech_stack or {}
                merged.update(tech_data)
                existing.tech_stack = merged
                await session.commit()
                return existing.id

            obs = Observation(
                asset_id=asset_id,
                tech_stack=tech_data,
            )
            session.add(obs)
            await session.flush()
            obs_id = obs.id
            await session.commit()
            return obs_id

    async def _save_vulnerability(
        self,
        target_id: int,
        asset_id: int | None,
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
            "event": "critical_alert",
            "alert_id": alert_id,
            "vulnerability_id": vuln_id,
            "message": message,
        })

    async def _get_asset_ip(self, asset_id: int) -> str | None:
        """Get the asset_value (IP/domain) for a given asset_id."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(Asset.id == asset_id)
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            return row
