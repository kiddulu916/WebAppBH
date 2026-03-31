"""Abstract base class for input validation testing tool wrappers."""

from __future__ import annotations

import asyncio
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from sqlalchemy import select, distinct, and_, or_, String
from sqlalchemy.types import JSON

from lib_webbh import (
    Alert,
    ApiSchema,
    Asset,
    JobState,
    Location,
    Observation,
    Parameter,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.input_validation.concurrency import WeightClass, get_semaphore

logger = setup_logger("input-validation-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# ---------------------------------------------------------------------------
# Constants for input validation
# ---------------------------------------------------------------------------

# Common injection payloads for various attack types
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "1' OR '1' = '1",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "`whoami`",
    "$(uname -a)",
]

# Regex patterns for detecting vulnerabilities
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d+",
    r"Microsoft SQL Server",
]

XSS_REFLECTION_PATTERNS = [
    r"<script[^>]*>alert\(.*\)</script>",
    r"<img[^>]*onerror[^>]*>",
]


class InputValidationTool(ABC):
    """Base class for all input validation testing tool wrappers.

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
    # Semaphore and execution wrapper
    # ------------------------------------------------------------------

    async def run_with_semaphore(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Wrap execute() with cooldown check, semaphore, and job state updates."""
        log = logger.bind(target_id=target_id, asset_type="job")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "vulnerable": 0, "skipped_cooldown": True}

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

            # 3. Execute the tool
            try:
                stats = await self.execute(
                    target, scope_manager, target_id, container_name, headers, **kwargs
                )
            except asyncio.TimeoutError:
                log.warning(f"{self.name} timed out after {TOOL_TIMEOUT}s")
                await push_task(f"events:{target_id}", {
                    "event": "TOOL_PROGRESS",
                    "container": container_name,
                    "tool": self.name,
                    "progress": 100,
                    "message": f"{self.name} timed out",
                })
                return {"found": 0, "vulnerable": 0, "skipped_cooldown": False}
            except Exception as e:
                log.error(f"{self.name} failed: {e}")
                return {"found": 0, "vulnerable": 0, "skipped_cooldown": False}

            # 4. Update job_state
            await self.update_tool_state(target_id, container_name)

            stats["skipped_cooldown"] = False

            # Emit TOOL_PROGRESS — finished
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": f"{self.name}: {stats.get('vulnerable', 0)} vulnerabilities found",
            })

            log.info(
                f"{self.name} complete",
                extra={"tool": self.name, **stats},
            )
            return stats

        finally:
            sem.release()

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
    # Query helpers (shared with VulnScanTool)
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
    # Input validation specific helpers
    # ------------------------------------------------------------------

    def get_injection_payloads(self, attack_type: str) -> list[str]:
        """Return common payloads for a given attack type."""
        payloads = {
            "xss": XSS_PAYLOADS,
            "sqli": SQL_INJECTION_PAYLOADS,
            "command": COMMAND_INJECTION_PAYLOADS,
        }
        return payloads.get(attack_type, [])

    def detect_vulnerability(self, response: str, attack_type: str) -> bool:
        """Check if response indicates a vulnerability for the given attack type."""
        patterns = {
            "sqli": SQL_ERROR_PATTERNS,
            "xss": XSS_REFLECTION_PATTERNS,
        }
        vuln_patterns = patterns.get(attack_type, [])
        for pattern in vuln_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        return False

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

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