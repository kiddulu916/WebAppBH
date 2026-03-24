"""Abstract base class for cloud testing tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from sqlalchemy import select

from lib_webbh import (
    Alert,
    Asset,
    CloudAsset,
    JobState,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.cloud_worker.concurrency import WeightClass

logger = setup_logger("cloud-test-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# ---------------------------------------------------------------------------
# Cloud URL patterns for detecting provider from URLs
# ---------------------------------------------------------------------------

CLOUD_URL_PATTERNS: list[str] = [
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "appspot.com",
    "firebaseio.com",
]

_PROVIDER_MAP: list[tuple[str, str]] = [
    ("s3.amazonaws.com", "aws"),
    ("blob.core.windows.net", "azure"),
    ("storage.googleapis.com", "gcp"),
    ("appspot.com", "gcp"),
    ("firebaseio.com", "gcp"),
]


def detect_provider(url: str) -> str | None:
    """Detect cloud provider from a URL. Returns 'aws', 'azure', 'gcp', or None."""
    lower = url.lower()
    for pattern, provider in _PROVIDER_MAP:
        if pattern in lower:
            return provider
    return None


class CloudTestTool(ABC):
    """Base class for all cloud testing tool wrappers.

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
        **kwargs,
    ) -> dict:
        """Run the tool against *target* and return a stats dict."""

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
    # Cloud asset query helpers
    # ------------------------------------------------------------------

    async def _get_cloud_assets(self, target_id: int) -> list[CloudAsset]:
        """Fetch all CloudAsset rows for a target."""
        async with get_session() as session:
            stmt = select(CloudAsset).where(CloudAsset.target_id == target_id)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_public_cloud_assets(self, target_id: int) -> list[CloudAsset]:
        """Fetch CloudAsset rows where is_public=True for a target."""
        async with get_session() as session:
            stmt = select(CloudAsset).where(
                CloudAsset.target_id == target_id,
                CloudAsset.is_public.is_(True),
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_cloud_urls_from_assets(
        self, target_id: int
    ) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets matching cloud URL patterns."""
        from sqlalchemy import or_

        async with get_session() as session:
            conditions = [
                Asset.asset_value.ilike(f"%{pattern}%")
                for pattern in CLOUD_URL_PATTERNS
            ]
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                or_(*conditions),
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    async def _save_cloud_asset(
        self,
        target_id: int,
        provider: str,
        asset_type: str,
        url: str,
        is_public: bool = False,
        findings: dict | None = None,
    ) -> int:
        """Upsert a CloudAsset row. Returns the cloud asset id."""
        async with get_session() as session:
            stmt = select(CloudAsset).where(
                CloudAsset.target_id == target_id,
                CloudAsset.url == url,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                existing.is_public = is_public
                if findings is not None:
                    existing.findings = findings
                await session.commit()
                return existing.id

            ca = CloudAsset(
                target_id=target_id,
                provider=provider,
                asset_type=asset_type,
                url=url,
                is_public=is_public,
                findings=findings,
            )
            session.add(ca)
            await session.flush()
            ca_id = ca.id
            await session.commit()
            return ca_id

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
