"""Abstract base class for client-side testing tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from lib_webbh import (
    Alert,
    JobState,
    Observation,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager, ScopeResult
from lib_webbh.infra_mixin import InfrastructureMixin

from workers.client_side.concurrency import WeightClass, get_semaphore

logger = setup_logger("client-side-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))


class ClientSideTool(InfrastructureMixin, ABC):
    """Base class for all client-side testing tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class attributes
    and implement ``build_command()`` and ``parse_output()``.
    """

    name: str
    weight_class: WeightClass

    @abstractmethod
    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        """Return the CLI command as a list of strings."""

    @abstractmethod
    def parse_output(self, stdout: str) -> list:
        """Parse tool stdout into a list of results.

        Returns:
            list[dict] with observation details for client-side findings
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
        credentials: dict | None = None,
    ) -> dict:
        """Full tool lifecycle: cooldown, subprocess, parse, DB insert.

        Returns stats dict: {found, inserted}.
        """
        log = logger.bind(target_id=target_id, asset_type="client_side")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "inserted": 0, "skipped_cooldown": True}

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
            cmd = self.build_command(target, credentials)
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
                return {"found": 0, "inserted": 0, "skipped_cooldown": False}
            except FileNotFoundError:
                log.error(f"{self.name} binary not found — is it installed?")
                return {"found": 0, "inserted": 0, "skipped_cooldown": False}

            # 4. Parse output
            raw_results = self.parse_output(stdout)
            found = len(raw_results)

            # 5. Insert observations
            inserted_count = 0
            for item in raw_results:
                inserted = await self._process_result(item, target_id, log)
                if inserted:
                    inserted_count += 1

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
                "inserted": inserted_count,
                "skipped_cooldown": False,
            }

            # Emit TOOL_PROGRESS — finished
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": f"{self.name}: {inserted_count} observations inserted",
            })

            log.info(
                f"{self.name} complete",
                extra={"tool": self.name, **stats},
            )
            return stats

        finally:
            sem.release()

    async def _process_result(self, item: dict, target_id: int, log) -> bool:
        """Process one parsed result into an Observation."""
        async with get_session() as session:
            observation = Observation(
                target_id=target_id,
                observation_type="client_side",
                title=item.get("title", f"{self.name} finding"),
                description=item.get("description", ""),
                severity=item.get("severity", "info"),
                data=item.get("data", {}),
                source_tool=self.name,
            )
            session.add(observation)
            await session.commit()

            # Emit NEW_OBSERVATION event
            await push_task(f"events:{target_id}", {
                "event": "NEW_OBSERVATION",
                "target_id": target_id,
                "observation_type": "client_side",
                "title": observation.title,
                "severity": observation.severity,
                "source_tool": self.name,
            })

            return True
