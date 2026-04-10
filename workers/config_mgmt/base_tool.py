"""Abstract base class for config management tool wrappers."""

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
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager, ScopeResult
from lib_webbh.shared_infra import is_shared_infra
from lib_webbh.infra_mixin import InfrastructureMixin

from workers.config_mgmt.concurrency import WeightClass, get_semaphore, get_tool_weight

logger = setup_logger("config-mgmt-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))


class ConfigMgmtTool(InfrastructureMixin, ABC):
    """Base class for all config management tool wrappers.

    Adds config-specific helpers:
    - check_response_for_info_leak() — scan response bodies for sensitive patterns
    - test_url_access() — check if a URL returns content vs 403/404
    - compare_responses() — diff two responses to detect subtle differences
    """

    name: str

    @property
    def weight_class(self) -> WeightClass:
        """Get the weight class for this tool."""
        return get_tool_weight(self.name)

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
            list[dict] with 'vulnerability' key (inserted as Vulnerability rows)
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

            return True

    async def _process_dict_result(self, item, scope_manager, target_id, log) -> bool | None:
        """Process a dict result (vulnerability, observation, etc)."""
        if "vulnerability" in item:
            return await self._process_vulnerability(item, target_id, log)
        elif "observation" in item:
            return await self._process_observation(item, target_id, log)
        # Add other dict types as needed
        return None

    async def _process_vulnerability(self, item, target_id, log) -> bool | None:
        """Process a vulnerability result."""
        vuln_data = item["vulnerability"]
        vuln_name = vuln_data.get("name", "")
        severity = vuln_data.get("severity", "info")
        description = vuln_data.get("description", "")
        location = vuln_data.get("location", "")

        async with get_session() as session:
            # Check for duplicate
            stmt = select(Vulnerability).where(
                Vulnerability.target_id == target_id,
                Vulnerability.name == vuln_name,
                Vulnerability.location == location,
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                return False

            vuln = Vulnerability(
                target_id=target_id,
                name=vuln_name,
                severity=severity,
                description=description,
                location=location,
                source_tool=self.name,
            )
            session.add(vuln)
            await session.commit()

            # Emit event
            await push_task(f"events:{target_id}", {
                "event": "NEW_VULNERABILITY",
                "target_id": target_id,
                "name": vuln_name,
                "severity": severity,
                "location": location,
                "source_tool": self.name,
            })

            return True

    async def _process_observation(self, item, target_id, log) -> bool | None:
        """Process an observation result."""
        obs_data = item["observation"]
        obs_type = obs_data.get("type", "")
        value = obs_data.get("value", "")
        details = obs_data.get("details", {})

        async with get_session() as session:
            # Check for duplicate
            stmt = select(Observation).where(
                Observation.target_id == target_id,
                Observation.observation_type == obs_type,
                Observation.value == value,
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                return False

            obs = Observation(
                target_id=target_id,
                observation_type=obs_type,
                value=value,
                details=details,
                source_tool=self.name,
            )
            session.add(obs)
            await session.commit()

            return True

    # Config-specific helper methods
    def check_response_for_info_leak(self, response_body: str) -> list[str]:
        """Scan response body for sensitive patterns."""
        patterns = [
            r"password\s*[:=]\s*\w+",
            r"api[_-]?key\s*[:=]\s*\w+",
            r"secret\s*[:=]\s*\w+",
            r"token\s*[:=]\s*\w+",
            r"database[_-]?url\s*[:=]\s*\w+",
        ]
        leaks = []
        import re
        for pattern in patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            leaks.extend(matches)
        return leaks

    async def test_url_access(self, url: str) -> dict:
        """Test if a URL returns content vs 403/404."""
        import aiohttp
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    return {
                        "status": resp.status,
                        "content_length": len(await resp.text()),
                        "content_type": resp.headers.get("content-type", ""),
                    }
        except Exception as e:
            return {"error": str(e)}

    def compare_responses(self, resp1: str, resp2: str) -> bool:
        """Return True if responses are different."""
        return resp1.strip() != resp2.strip()