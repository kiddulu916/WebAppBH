"""Abstract base class for recon tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from lib_webbh import (
    Asset,
    Alert,
    JobState,
    Location,
    Observation,
    Parameter,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager, ScopeResult
from lib_webbh.shared_infra import is_shared_infra

from workers.recon_core.concurrency import WeightClass, get_semaphore

logger = setup_logger("recon-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# Patterns and ports that trigger critical alerts
CRITICAL_PATHS = {".git", ".env", ".DS_Store", "wp-config.php", ".htpasswd", "web.config"}
CRITICAL_PORTS = {3389, 5900, 27017, 9200, 6379, 11211, 2375}


class ReconTool(ABC):
    """Base class for all recon tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class attributes
    and implement ``build_command()`` and ``parse_output()``.
    """

    name: str
    weight_class: WeightClass

    @abstractmethod
    def build_command(self, target, headers: dict | None = None) -> list[str]:
        """Return the CLI command as a list of strings."""

    @abstractmethod
    def parse_output(self, stdout: str) -> list:
        """Parse tool stdout into a list of results.

        Returns:
            list[str] for domain/IP strings (inserted as Asset rows)
            list[dict] with 'port' key (inserted as Location rows)
            list[dict] with 'param_name' key (inserted as Parameter rows)
        """

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

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        """Full tool lifecycle: cooldown, subprocess, parse, scope-check, DB insert.

        Returns stats dict: {found, in_scope, new, skipped_cooldown}.
        """
        log = logger.bind(target_id=target_id, asset_type="job")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # 2. Acquire semaphore
        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            log.info(f"Running {self.name}", extra={"tool": self.name})

            # Emit TOOL_PROGRESS — started
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 0,
                "message": f"{self.name} started",
            })

            # 3. Build and run command
            cmd = self.build_command(target, headers)
            try:
                stdout = await self.run_subprocess(cmd)
            except asyncio.TimeoutError:
                log.warning(f"{self.name} timed out after {TOOL_TIMEOUT}s")
                await push_task(f"events:{target_id}", {
                    "event": "TOOL_PROGRESS",
                    "container": container_name,
                    "tool": self.name,
                    "progress": 100,
                    "message": f"{self.name} timed out",
                })
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
            except FileNotFoundError:
                log.error(f"{self.name} binary not found — is it installed?")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # 4. Parse output
            raw_results = self.parse_output(stdout)
            found = len(raw_results)

            # 5. Scope-check and insert
            new_count = 0
            in_scope_count = 0

            for item in raw_results:
                inserted = await self._process_result(
                    item, scope_manager, target_id, log
                )
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            # 6. Update job_state
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

            stats = {
                "found": found,
                "in_scope": in_scope_count,
                "new": new_count,
                "skipped_cooldown": False,
            }

            # Emit TOOL_PROGRESS — finished
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })

            log.info(
                f"{self.name} complete",
                extra={"tool": self.name, **stats},
            )
            return stats

        finally:
            sem.release()

    async def _process_result(self, item, scope_manager, target_id, log) -> bool | None:
        """Process one parsed result. Returns True=new, False=dup, None=out-of-scope."""
        if isinstance(item, dict):
            return await self._process_dict_result(item, scope_manager, target_id, log)

        # String result — domain/IP asset
        scope_result = scope_manager.is_in_scope(item)
        if not scope_result.in_scope:
            return None

        # Shared-infra drift detection
        tech_data: dict | None = None
        infra = is_shared_infra(item)
        if infra.is_shared:
            log.warning(
                "Shared infra detected — flagging for review",
                extra={"asset": item, "provider": infra.provider, "category": infra.category},
            )
            tech_data = {
                "shared_infra": True,
                "shared_infra_provider": infra.provider,
                "shared_infra_category": infra.category,
            }
            await push_task(f"events:{target_id}", {
                "event": "SCOPE_DRIFT",
                "target_id": target_id,
                "asset_value": item,
                "provider": infra.provider,
                "category": infra.category,
            })

        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type == scope_result.asset_type,
                Asset.asset_value == scope_result.normalized,
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                return False

            asset = Asset(
                target_id=target_id,
                asset_type=scope_result.asset_type,
                asset_value=scope_result.normalized,
                source_tool=self.name,
                tech=tech_data,
            )
            session.add(asset)
            await session.commit()

            # Emit NEW_ASSET event for live dashboard updates
            await push_task(f"events:{target_id}", {
                "event": "NEW_ASSET",
                "target_id": target_id,
                "asset_type": scope_result.asset_type,
                "asset_value": scope_result.normalized,
                "source_tool": self.name,
            })

            if scope_result.path:
                await self._check_critical_path(
                    scope_result.path, scope_result.normalized, target_id, log
                )

            return True

    async def _process_dict_result(self, item, scope_manager, target_id, log) -> bool | None:
        """Process a dict result (port or param)."""
        if "port" in item:
            ip = item.get("ip", item.get("host", ""))
            port = item["port"]
            protocol = item.get("protocol", "tcp")

            scope_result = scope_manager.is_in_scope(ip)
            if not scope_result.in_scope:
                return None

            # Shared-infra drift detection
            infra = is_shared_infra(ip)
            if infra.is_shared:
                log.warning(
                    "Shared infra detected — flagging for review",
                    extra={"asset": ip, "provider": infra.provider, "category": infra.category},
                )
                await push_task(f"events:{target_id}", {
                    "event": "SCOPE_DRIFT",
                    "target_id": target_id,
                    "asset_value": ip,
                    "provider": infra.provider,
                    "category": infra.category,
                })

            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == scope_result.normalized,
                )
                result = await session.execute(stmt)
                asset = result.scalar_one_or_none()
                if asset is None:
                    tech_data = None
                    if infra.is_shared:
                        tech_data = {
                            "shared_infra": True,
                            "shared_infra_provider": infra.provider,
                            "shared_infra_category": infra.category,
                        }
                    asset = Asset(
                        target_id=target_id,
                        asset_type=scope_result.asset_type,
                        asset_value=scope_result.normalized,
                        source_tool=self.name,
                        tech=tech_data,
                    )
                    session.add(asset)
                    await session.flush()

                loc_stmt = select(Location).where(
                    Location.asset_id == asset.id,
                    Location.port == port,
                    Location.protocol == protocol,
                )
                loc_result = await session.execute(loc_stmt)
                if loc_result.scalar_one_or_none() is not None:
                    return False

                location = Location(
                    asset_id=asset.id,
                    port=port,
                    protocol=protocol,
                    service=item.get("service"),
                    state="open",
                )
                session.add(location)
                await session.commit()

                if port in CRITICAL_PORTS:
                    await self._create_alert(
                        target_id,
                        f"Critical port {port} open on {scope_result.normalized}",
                        log,
                    )

                return True

        elif "param_name" in item:
            url = item.get("source_url", "")
            scope_result = scope_manager.is_in_scope(url) if url else None

            if not scope_result or not scope_result.in_scope:
                return None

            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == scope_result.normalized,
                )
                result = await session.execute(stmt)
                asset = result.scalar_one_or_none()
                if asset is None:
                    return None

                param_stmt = select(Parameter).where(
                    Parameter.asset_id == asset.id,
                    Parameter.param_name == item["param_name"],
                )
                param_result = await session.execute(param_stmt)
                if param_result.scalar_one_or_none() is not None:
                    return False

                param = Parameter(
                    asset_id=asset.id,
                    param_name=item["param_name"],
                    param_value=item.get("param_value"),
                    source_url=url,
                )
                session.add(param)
                await session.commit()
                return True

        elif "tech" in item:
            host = item.get("host", "")
            new_techs = item.get("tech", [])
            if not host or not new_techs:
                return None

            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                return None

            # Shared-infra drift detection
            infra = is_shared_infra(host)
            if infra.is_shared:
                log.warning(
                    "Shared infra detected — flagging for review",
                    extra={"asset": host, "provider": infra.provider, "category": infra.category},
                )
                await push_task(f"events:{target_id}", {
                    "event": "SCOPE_DRIFT",
                    "target_id": target_id,
                    "asset_value": host,
                    "provider": infra.provider,
                    "category": infra.category,
                })

            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == scope_result.normalized,
                )
                result = await session.execute(stmt)
                asset = result.scalar_one_or_none()
                if asset is None:
                    return None

                # Merge tech list — handle both list and dict formats
                existing = asset.tech if isinstance(asset.tech, dict) else {}
                if isinstance(asset.tech, list):
                    existing_set = set(asset.tech)
                    merged_set = existing_set | set(new_techs)
                    if merged_set == existing_set and not infra.is_shared:
                        return False
                    asset.tech = sorted(merged_set)
                else:
                    existing_set = set()
                    asset.tech = sorted(set(new_techs))

                # Merge shared-infra metadata into tech column
                if infra.is_shared:
                    if isinstance(asset.tech, list):
                        asset.tech = {
                            "stack": asset.tech,
                            "shared_infra": True,
                            "shared_infra_provider": infra.provider,
                            "shared_infra_category": infra.category,
                        }
                    else:
                        tech_dict = asset.tech if isinstance(asset.tech, dict) else {}
                        tech_dict["shared_infra"] = True
                        tech_dict["shared_infra_provider"] = infra.provider
                        tech_dict["shared_infra_category"] = infra.category
                        asset.tech = tech_dict

                flag_modified(asset, "tech")
                await session.commit()
                return True

        return None

    async def _check_critical_path(self, path, domain, target_id, log) -> None:
        """Check if a discovered path matches a critical pattern."""
        path_lower = path.lower().lstrip("/")
        for pattern in CRITICAL_PATHS:
            if pattern in path_lower:
                await self._create_alert(
                    target_id,
                    f"Exposed {pattern} at {domain}{path}",
                    log,
                )
                break

    async def _create_alert(self, target_id, message, log) -> None:
        """Write alert to DB and push to Redis for SSE."""
        log.warning(f"CRITICAL: {message}")
        async with get_session() as session:
            alert = Alert(
                target_id=target_id,
                alert_type="critical",
                message=message,
            )
            session.add(alert)
            await session.commit()
            alert_id = alert.id

        await push_task(f"events:{target_id}", {
            "event": "CRITICAL_ALERT",
            "alert_id": alert_id,
            "message": message,
        })
