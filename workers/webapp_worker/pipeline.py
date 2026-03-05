"""Web-application analysis pipeline: 6 sequential stages with browser lifecycle."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import WebAppTool
from workers.webapp_worker.browser import BrowserManager
from workers.webapp_worker.tools import (
    JsCrawler,
    LinkFinder, JsMiner, Mantra, SecretFinder,
    PostMessage, DomSinkAnalyzer, StorageAuditor,
    SourcemapDetector, WebSocketAnalyzer,
    HeaderAuditor, CookieAuditor, CorsTester, FormAnalyzer,
    SensitivePaths, RobotsSitemap, GraphqlProber,
    OpenApiDetector, OpenRedirect,
    NewmanProber,
)

logger = setup_logger("webapp-pipeline")

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------

BROWSER_STAGES = {"js_discovery", "browser_security"}
HTTP_STAGES = {"http_security", "path_api_discovery"}


@dataclass
class Stage:
    name: str
    tool_classes: list[type[WebAppTool]]


STAGES: list[Stage] = [
    Stage("js_discovery",       [JsCrawler]),
    Stage("static_js_analysis", [LinkFinder, JsMiner, Mantra, SecretFinder]),
    Stage("browser_security",   [PostMessage, DomSinkAnalyzer, StorageAuditor,
                                 SourcemapDetector, WebSocketAnalyzer]),
    Stage("http_security",      [HeaderAuditor, CookieAuditor, CorsTester, FormAnalyzer]),
    Stage("path_api_discovery", [SensitivePaths, RobotsSitemap, GraphqlProber,
                                 OpenApiDetector, OpenRedirect]),
    Stage("api_probing",        [NewmanProber]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    """Rebuild the STAGE_INDEX mapping from the current STAGES list."""
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


# Build once at import time.
_rebuild_index()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Orchestrates the 6-stage web-app analysis pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str) -> None:
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        _rebuild_index()

        completed_phase = await self._get_completed_phase()
        start_index = 0

        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        browser_mgr: BrowserManager | None = None

        try:
            for stage in STAGES[start_index:]:
                self.log.info(f"Starting stage: {stage.name}")
                await self._update_phase(stage.name)

                # Browser lifecycle management
                browser_mgr = await self._manage_browser(stage.name, browser_mgr)

                # Build extra kwargs based on stage type
                kwargs: dict = {}
                if stage.name in BROWSER_STAGES and browser_mgr is not None:
                    kwargs["browser"] = browser_mgr
                if stage.name in HTTP_STAGES:
                    kwargs["http_client"] = self._get_http_client(headers)

                stats = await self._run_stage(
                    stage, target, scope_manager, headers, **kwargs
                )

                self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
                await push_task(f"events:{self.target_id}", {
                    "event": "stage_complete",
                    "stage": stage.name,
                    "stats": stats,
                })

                # Shut down browser after browser_security stage
                if stage.name == "browser_security" and browser_mgr is not None:
                    await browser_mgr.shutdown()
                    browser_mgr = None

        finally:
            # Ensure browser is cleaned up on unexpected exit
            if browser_mgr is not None:
                await browser_mgr.shutdown()

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "pipeline_complete",
            "target_id": self.target_id,
        })

    # ------------------------------------------------------------------
    # Browser lifecycle
    # ------------------------------------------------------------------

    async def _manage_browser(
        self, stage_name: str, browser_mgr: BrowserManager | None
    ) -> BrowserManager | None:
        """Start a BrowserManager if the stage needs one and none exists."""
        if stage_name in BROWSER_STAGES and browser_mgr is None:
            browser_mgr = BrowserManager()
            await browser_mgr.start()
            self.log.info("BrowserManager started for browser stage")
        return browser_mgr

    # ------------------------------------------------------------------
    # HTTP client factory
    # ------------------------------------------------------------------

    @staticmethod
    def _get_http_client(headers: dict | None = None) -> httpx.AsyncClient:
        """Create a configured httpx.AsyncClient for HTTP stages."""
        return httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            limits=httpx.Limits(max_connections=10),
            headers=headers or {},
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Stage runner
    # ------------------------------------------------------------------

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run all tools in a stage concurrently, return aggregated stats."""
        tools = [cls() for cls in stage.tool_classes]

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
                **kwargs,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(
                    f"Tool failed in {stage.name}", extra={"error": str(r)}
                )
                continue
            aggregated["found"] += r.get("found", 0)
            aggregated["in_scope"] += r.get("in_scope", 0)
            aggregated["new"] += r.get("new", 0)

        # Close http_client if one was provided
        http_client = kwargs.get("http_client")
        if http_client is not None:
            await http_client.aclose()

        return aggregated

    # ------------------------------------------------------------------
    # Checkpoint helpers
    # ------------------------------------------------------------------

    async def _get_completed_phase(self) -> str | None:
        """Query job_state for the last completed phase."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
                JobState.status == "COMPLETED",
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            return job.current_phase if job else None

    async def _update_phase(self, phase: str) -> None:
        """Update job_state with current phase."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.current_phase = phase
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self) -> None:
        """Mark the job as COMPLETED."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()
