"""Abstract base class for API testing tool wrappers."""

from __future__ import annotations

import asyncio
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta

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

from workers.api_worker.concurrency import WeightClass

logger = setup_logger("api-test-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_URL_PATTERNS = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/swagger", "/openapi", "/rest/"]
OAUTH_PATH_PATTERNS = ["/oauth/", "/authorize", "/callback", "/auth/", "/login", "/token"]
PATH_PARAM_RE = re.compile(r"/:(\w+)|/\{(\w+)\}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


class ApiTestTool(ABC):
    """Base class for all API testing tool wrappers.

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
    # Tech-stack helper
    # ------------------------------------------------------------------

    async def _get_tech_stack(self, asset_id: int) -> dict | None:
        """Return latest observations.tech_stack JSON for an asset."""
        async with get_session() as session:
            stmt = (
                select(Observation.tech_stack)
                .where(
                    Observation.asset_id == asset_id,
                    Observation.tech_stack.isnot(None),
                )
                .order_by(Observation.created_at.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            return row

    # ------------------------------------------------------------------
    # API-specific query helpers
    # ------------------------------------------------------------------

    async def _get_api_urls(self, target_id: int) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets whose value matches API patterns."""
        async with get_session() as session:
            conditions = [
                Asset.asset_value.ilike(f"%{pattern}%")
                for pattern in API_URL_PATTERNS
            ]
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "url",
                or_(*conditions),
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    async def _get_api_schemas(self, target_id: int) -> list[ApiSchema]:
        """Return all ApiSchema rows for a target."""
        async with get_session() as session:
            stmt = select(ApiSchema).where(ApiSchema.target_id == target_id)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_jwt_tokens(self, target_id: int) -> list[str]:
        """Extract JWT tokens from observation headers for a target.

        Queries observations.headers for Authorization Bearer tokens
        matching the JWT regex pattern.
        """
        tokens: list[str] = []
        async with get_session() as session:
            stmt = (
                select(Observation.headers)
                .join(Asset, Asset.id == Observation.asset_id)
                .where(
                    Asset.target_id == target_id,
                    Observation.headers.isnot(None),
                )
            )
            result = await session.execute(stmt)
            for row in result.scalars().all():
                if not isinstance(row, dict):
                    continue
                for key, value in row.items():
                    if isinstance(value, str):
                        matches = JWT_RE.findall(value)
                        tokens.extend(matches)
        return tokens

    async def _get_tech_filtered_urls(
        self, target_id: int, techs: list[str]
    ) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` where tech_stack contains any tech string.

        Joins Asset+Observation and checks tech_stack JSON cast to String
        for ILIKE matches against each tech keyword.
        """
        async with get_session() as session:
            tech_conditions = [
                Observation.tech_stack.cast(String).ilike(f"%{tech}%")
                for tech in techs
            ]
            stmt = (
                select(distinct(Asset.id), Asset.asset_value)
                .join(Observation, Observation.asset_id == Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Observation.tech_stack.isnot(None),
                    or_(*tech_conditions),
                )
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    async def _get_oauth_urls(self, target_id: int) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets matching OAuth path patterns."""
        async with get_session() as session:
            conditions = [
                Asset.asset_value.ilike(f"%{pattern}%")
                for pattern in OAUTH_PATH_PATTERNS
            ]
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "url",
                or_(*conditions),
            )
            result = await session.execute(stmt)
            return [(row[0], row[1]) for row in result.all()]

    # ------------------------------------------------------------------
    # API schema persistence
    # ------------------------------------------------------------------

    async def _save_api_schema(
        self,
        target_id: int,
        asset_id: int | None,
        method: str,
        path: str,
        params: dict | None = None,
        auth_required: bool | None = None,
        content_type: str | None = None,
        source_tool: str | None = None,
        spec_type: str | None = None,
    ) -> int:
        """Upsert an ApiSchema row. Returns the schema id.

        Selects existing by (target_id, asset_id, method, path); if found
        updates non-None fields; if not found inserts a new row.
        Handles asset_id=None correctly using .is_(None).
        """
        async with get_session() as session:
            # Build WHERE clause, handling asset_id=None
            if asset_id is None:
                asset_condition = ApiSchema.asset_id.is_(None)
            else:
                asset_condition = ApiSchema.asset_id == asset_id

            stmt = select(ApiSchema).where(
                ApiSchema.target_id == target_id,
                asset_condition,
                ApiSchema.method == method,
                ApiSchema.path == path,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                # Update non-None fields
                if params is not None:
                    existing.params = params
                if auth_required is not None:
                    existing.auth_required = auth_required
                if content_type is not None:
                    existing.content_type = content_type
                if source_tool is not None:
                    existing.source_tool = source_tool
                if spec_type is not None:
                    existing.spec_type = spec_type
                await session.commit()
                return existing.id

            schema = ApiSchema(
                target_id=target_id,
                asset_id=asset_id,
                method=method,
                path=path,
                params=params,
                auth_required=auth_required,
                content_type=content_type,
                source_tool=source_tool or self.name,
                spec_type=spec_type,
            )
            session.add(schema)
            await session.flush()
            schema_id = schema.id
            await session.commit()
            return schema_id

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
            "event": "critical_alert",
            "alert_id": alert_id,
            "vulnerability_id": vuln_id,
            "message": message,
        })
