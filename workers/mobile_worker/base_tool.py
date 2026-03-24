"""Abstract base class for mobile testing tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from lib_webbh import (
    Alert,
    Asset,
    JobState,
    MobileApp,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("mobile-test-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))
MOBILE_BINARIES_DIR = os.environ.get(
    "MOBILE_BINARIES_DIR", "/app/shared/mobile_binaries"
)
MOBILE_ANALYSIS_DIR = os.environ.get(
    "MOBILE_ANALYSIS_DIR", "/app/shared/mobile_analysis"
)

BINARY_EXTENSIONS = (".apk", ".ipa")


class MobileTestTool(ABC):
    """Base class for all mobile testing tool wrappers.

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
    # Binary query helpers
    # ------------------------------------------------------------------

    async def _get_binary_urls(self, target_id: int) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets ending in .apk/.ipa."""
        async with get_session() as session:
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "url",
            )
            result = await session.execute(stmt)
            return [
                (row[0], row[1])
                for row in result.all()
                if any(row[1].lower().endswith(ext) for ext in BINARY_EXTENSIONS)
            ]

    def _scan_drop_folder(self, target_id: int) -> list[str]:
        """List APK/IPA files from the manual drop folder."""
        folder = Path(MOBILE_BINARIES_DIR) / str(target_id)
        if not folder.is_dir():
            return []
        return [
            str(f)
            for f in folder.iterdir()
            if f.is_file() and f.suffix.lower() in BINARY_EXTENSIONS
        ]

    # ------------------------------------------------------------------
    # MobileApp helpers
    # ------------------------------------------------------------------

    async def _get_mobile_app(
        self, target_id: int, package_name: str
    ) -> MobileApp | None:
        """Fetch a MobileApp row by (target_id, package_name)."""
        async with get_session() as session:
            stmt = select(MobileApp).where(
                MobileApp.target_id == target_id,
                MobileApp.package_name == package_name,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def _save_mobile_app(
        self,
        target_id: int,
        platform: str,
        package_name: str,
        version: str | None = None,
        asset_id: int | None = None,
        permissions: dict | None = None,
        signing_info: dict | None = None,
        mobsf_score: float | None = None,
        decompiled_path: str | None = None,
        source_url: str | None = None,
        source_tool: str | None = None,
    ) -> int:
        """Upsert a MobileApp row. Returns the app id."""
        async with get_session() as session:
            stmt = select(MobileApp).where(
                MobileApp.target_id == target_id,
                MobileApp.platform == platform,
                MobileApp.package_name == package_name,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                if version is not None:
                    existing.version = version
                if asset_id is not None:
                    existing.asset_id = asset_id
                if permissions is not None:
                    existing.permissions = permissions
                if signing_info is not None:
                    existing.signing_info = signing_info
                if mobsf_score is not None:
                    existing.mobsf_score = mobsf_score
                if decompiled_path is not None:
                    existing.decompiled_path = decompiled_path
                if source_url is not None:
                    existing.source_url = source_url
                if source_tool is not None:
                    existing.source_tool = source_tool
                await session.commit()
                return existing.id

            app = MobileApp(
                target_id=target_id,
                asset_id=asset_id,
                platform=platform,
                package_name=package_name,
                version=version,
                permissions=permissions,
                signing_info=signing_info,
                mobsf_score=mobsf_score,
                decompiled_path=decompiled_path,
                source_url=source_url,
                source_tool=source_tool or self.name,
            )
            session.add(app)
            await session.flush()
            app_id = app.id
            await session.commit()
            return app_id

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
