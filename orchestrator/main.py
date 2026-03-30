"""WebAppBH Framework Orchestrator — FastAPI application.

Endpoints
---------
POST  /api/v1/targets              – initialise a new scan target
GET   /api/v1/targets              – list all targets
GET   /api/v1/assets               – list assets for a target (with locations)
GET   /api/v1/vulnerabilities      – list vulnerabilities for a target
GET   /api/v1/cloud_assets         – list cloud assets for a target
GET   /api/v1/alerts               – list alerts for a target
PATCH /api/v1/alerts/{alert_id}    – update alert read status
PATCH /api/v1/targets/{target_id}  – update target profile (headers, rate limits)
DELETE /api/v1/targets/{target_id} – permanently delete a target
GET   /api/v1/status               – real-time job states
POST  /api/v1/control              – pause / stop / restart workers
POST  /api/v1/kill                 – hard-kill all active workers
GET   /api/v1/stream/{id}          – SSE event stream per target
POST  /api/v1/targets/{id}/reports – trigger report generation
GET   /api/v1/targets/{id}/reports – list generated reports
GET   /api/v1/targets/{id}/reports/{filename} – download a report
POST  /api/v1/targets/{id}/rescan  – snapshot assets and queue rescan
GET   /api/v1/vulnerabilities/{id}/draft – draft vuln report for platform
GET   /api/v1/targets/{id}/graph   – attack graph (nodes + edges)
GET   /api/v1/targets/{id}/attack-paths – exploitable vuln chains by asset
GET   /api/v1/targets/{id}/execution    – pipeline execution state
POST  /api/v1/targets/{id}/apply-playbook – apply a playbook to a target
GET   /api/v1/assets/{id}/locations      – locations for an asset
GET   /api/v1/assets/{id}/vulnerabilities – vulns for an asset
GET   /api/v1/assets/{id}/cloud          – cloud assets for an asset's target
GET   /api/v1/targets/{id}/correlations – correlated vulnerability groups
GET   /api/v1/queue_health            – queue depth health status
POST  /api/v1/bounties               – create a bounty submission
GET   /api/v1/bounties               – list bounty submissions
PATCH /api/v1/bounties/{bounty_id}   – update bounty submission
GET   /api/v1/bounties/stats         – ROI stats
GET   /api/v1/search                 – global search across assets & vulns
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import pathlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import func, inspect, or_, select, text
from sqlalchemy.orm import attributes, selectinload

from lib_webbh import (
    Alert,
    ApiSchema,
    Asset,
    AssetSnapshot,
    Base,
    BountySubmission,
    CloudAsset,
    CustomPlaybook,
    Identity,
    JobState,
    Location,
    MobileApp,
    Observation,
    Parameter,
    ScheduledScan,
    ScopeViolation,
    Target,
    Vulnerability,
    get_engine,
    get_session,
    is_valid_cron,
    next_run,
    push_task,
    setup_logger,
    enrich_shodan,
    enrich_securitytrails,
    get_available_intel_sources,
)
import lib_webbh.intel_enrichment as _intel_mod
from lib_webbh.messaging import get_redis
from lib_webbh.playbooks import BUILTIN_PLAYBOOKS

from orchestrator import event_engine, worker_manager

logger = setup_logger("orchestrator")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("WEB_APP_BH_API_KEY", "")
# * Comma-separated origins for browser clients (dashboard on :3000, etc.)
_CORS_RAW = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001",
)
CORS_ORIGINS = [o.strip() for o in _CORS_RAW.split(",") if o.strip()]
SHARED_CONFIG = Path(os.environ.get("SHARED_CONFIG_DIR", "/app/shared/config"))
SHARED_RAW = Path(os.environ.get("SHARED_RAW_DIR", "/app/shared/raw"))
SHARED_REPORTS = Path(os.environ.get("SHARED_REPORTS_DIR", "/app/shared/reports"))

# ---------------------------------------------------------------------------
# Security — X-API-KEY header
# ---------------------------------------------------------------------------
_api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)


async def verify_api_key(api_key: str | None = Depends(_api_key_header)) -> str:
    if not API_KEY:
        return "no-auth-configured"
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class TargetCreate(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=255)
    base_domain: str = Field(..., min_length=3, max_length=255)
    target_profile: Optional[dict] = None
    playbook: str = Field(default="wide_recon", max_length=100)


class ControlAction(BaseModel):
    container_name: str = Field(..., min_length=1, max_length=200)
    action: str = Field(..., description="pause | stop | restart | unpause")


class AlertUpdate(BaseModel):
    is_read: bool


class TargetProfileUpdate(BaseModel):
    custom_headers: Optional[dict] = None
    rate_limits: Optional[dict] = None


class ReportCreate(BaseModel):
    formats: list[Literal["hackerone_md", "bugcrowd_md", "executive_pdf", "technical_pdf"]] = Field(description="Report formats to generate")
    platform: Literal["hackerone", "bugcrowd"] = Field(default="hackerone", description="Target platform")


class BountyCreate(BaseModel):
    target_id: int = Field(..., gt=0)
    vulnerability_id: int = Field(..., gt=0)
    platform: str = Field(..., min_length=1, max_length=50)
    status: str = Field(default="submitted", max_length=50)
    submission_url: Optional[str] = Field(default=None, max_length=2000)
    expected_payout: Optional[float] = Field(default=None, ge=0)
    notes: Optional[str] = None


class BountyUpdate(BaseModel):
    status: Optional[str] = Field(default=None, max_length=50)
    actual_payout: Optional[float] = Field(default=None, ge=0)
    submission_url: Optional[str] = Field(default=None, max_length=2000)
    notes: Optional[str] = None


class ScheduleCreate(BaseModel):
    target_id: int = Field(..., gt=0)
    cron_expression: str = Field(..., min_length=5, max_length=100)
    playbook: str = Field(default="wide_recon", max_length=100)


class ScheduleUpdate(BaseModel):
    enabled: Optional[bool] = None
    cron_expression: Optional[str] = None
    playbook: Optional[str] = None


class ApiKeyUpdate(BaseModel):
    shodan_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None


class PlaybookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    stages: list[dict] = Field(..., min_length=1)
    concurrency: dict = Field(default={"heavy": 2, "light": 4})


class PlaybookUpdate(BaseModel):
    description: Optional[str] = None
    stages: Optional[list[dict]] = None
    concurrency: Optional[dict] = None


class RerunRequest(BaseModel):
    target_id: int = Field(..., gt=0)
    playbook_name: str = Field(..., min_length=1, max_length=100)


# ---------------------------------------------------------------------------
# Schema sync — add columns that exist in ORM models but not in the DB
# ---------------------------------------------------------------------------
def _add_missing_columns(connection) -> None:
    """Compare ORM metadata to live DB and ALTER TABLE for missing columns."""
    inspector = inspect(connection)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        db_columns = {c["name"] for c in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name not in db_columns:
                col_type = col.type.compile(dialect=connection.dialect)
                nullable = "NULL" if col.nullable else "NOT NULL"
                ddl = f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {col_type} {nullable}'
                logger.info("Adding missing column", extra={"ddl": ddl})
                connection.execute(text(ddl))


# ---------------------------------------------------------------------------
# Lifespan — start / stop background tasks
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Orchestrator starting")

    # Ensure tables exist (idempotent) and sync missing columns
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)

    if not API_KEY:
        logger.warning("WEB_APP_BH_API_KEY is not set — all endpoints are unauthenticated")

    # Load persisted intel API keys from .env.intel if available
    env_intel_path = pathlib.Path("/app/shared/config/.env.intel")
    if env_intel_path.exists():
        for line in env_intel_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if value and key in ("SHODAN_API_KEY", "SECURITYTRAILS_API_KEY"):
                    os.environ.setdefault(key, value)
        logger.info("Loaded intel API keys from .env.intel")

    # Initialize resource guard and event engine
    from orchestrator.resource_guard import ResourceGuard
    from orchestrator.event_engine import EventEngine

    resource_guard = ResourceGuard()
    event_engine = EventEngine(resource_guard)

    # Set guard for API endpoints
    set_guard(resource_guard)

    # Start background tasks
    engine_task = asyncio.create_task(event_engine.run(), name="event-engine")
    logger.info("Background tasks started")

    yield

    # Shutdown
    engine_task.cancel()
    try:
        await engine_task
    except asyncio.CancelledError:
        pass
    logger.info("Orchestrator stopped")


app = FastAPI(
    title="WebAppBH Orchestrator",
    version="0.1.0",
    lifespan=lifespan,
    dependencies=[Depends(verify_api_key)],
)


# ---------------------------------------------------------------------------
# Health endpoint — excluded from auth for Docker healthchecks
# ---------------------------------------------------------------------------
_health_router = APIRouter()


@_health_router.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(_health_router)

from orchestrator.routes.campaigns import router as campaigns_router
app.include_router(campaigns_router)

from orchestrator.routes.resources import router as resources_router, set_guard
app.include_router(resources_router)

from orchestrator.rate_limit import rate_limit_check  # noqa: E402
from orchestrator.metrics import metrics_response, api_latency, targets_created, bounties_submitted, scans_triggered, connected_sse_clients  # noqa: E402
import time as _time  # noqa: E402


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    await rate_limit_check(request)
    return await call_next(request)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", uuid4().hex)
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = _time.time()
    response = await call_next(request)
    duration = _time.time() - start
    # Skip metrics endpoint itself
    if request.url.path != "/metrics":
        api_latency.labels(
            method=request.method,
            endpoint=request.url.path,
        ).observe(duration)
    return response


# * Outermost: answer OPTIONS preflight before API-key deps and route method checks
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    return metrics_response()


# ---------------------------------------------------------------------------
# POST /api/v1/targets — initialise a new scan
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets", status_code=201)
async def create_target(body: TargetCreate):
    # Single-target enforcement
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]
    async with get_session() as session:
        active_count = (await session.execute(
            select(func.count(JobState.id)).where(JobState.status.in_(active_statuses))
        )).scalar()
        if active_count > 0:
            raise HTTPException(
                status_code=409,
                detail="Another target is currently active. Stop it before starting a new target.",
            )

    async with get_session() as session:
        target = Target(
            company_name=body.company_name,
            base_domain=body.base_domain,
            target_profile=body.target_profile,
            last_playbook=body.playbook,
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)

    # Write target_profile.json to shared volume
    profile_dir = SHARED_CONFIG / str(target.id)
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_path = profile_dir / "target_profile.json"
    profile_path.write_text(json.dumps({
        "target_id": target.id,
        "company_name": target.company_name,
        "base_domain": target.base_domain,
        "target_profile": body.target_profile or {},
    }, indent=2))

    # Write playbook.json
    from lib_webbh.playbooks import get_playbook
    playbook_config = get_playbook(body.playbook)
    (profile_dir / "playbook.json").write_text(
        json.dumps(playbook_config.to_dict(), indent=2)
    )

    # Generate tool-specific configs from target profile
    _generate_tool_configs(target.id, body.target_profile or {})

    logger.info(
        "Target initialised",
        extra={"target_id": target.id, "domain": body.base_domain},
    )
    targets_created.inc()

    return {
        "target_id": target.id,
        "company_name": target.company_name,
        "base_domain": target.base_domain,
        "profile_path": str(profile_path),
        "playbook": playbook_config.name,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/status — real-time job states
# ---------------------------------------------------------------------------
@app.get("/api/v1/status")
async def get_status(target_id: int | None = None):
    async with get_session() as session:
        stmt = select(JobState)
        if target_id is not None:
            stmt = stmt.where(JobState.target_id == target_id)
        result = await session.execute(stmt)
        jobs = result.scalars().all()

    return {
        "jobs": [
            {
                "id": j.id,
                "target_id": j.target_id,
                "container_name": j.container_name,
                "current_phase": j.current_phase,
                "status": j.status,
                "last_seen": j.last_seen.isoformat() if j.last_seen else None,
                "last_tool_executed": j.last_tool_executed,
                "created_at": j.created_at.isoformat() if j.created_at else None,
                "updated_at": j.updated_at.isoformat() if j.updated_at else None,
            }
            for j in jobs
        ],
    }


# ---------------------------------------------------------------------------
# POST /api/v1/control — pause / stop / restart workers
# ---------------------------------------------------------------------------
@app.post("/api/v1/control")
async def control_worker(body: ControlAction):
    if not body.container_name.startswith("webbh-"):
        raise HTTPException(status_code=400, detail="Can only control webbh worker containers")

    actions = {
        "pause": worker_manager.pause_worker,
        "stop": worker_manager.stop_worker,
        "restart": worker_manager.restart_worker,
        "unpause": worker_manager.unpause_worker,
    }
    fn = actions.get(body.action)
    if fn is None:
        raise HTTPException(status_code=400, detail=f"Unknown action: {body.action}")

    success = await fn(body.container_name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Container '{body.container_name}' not found or action failed")

    # Update job_state to reflect the action
    new_status = {"pause": "PAUSED", "stop": "STOPPED", "restart": "RUNNING", "unpause": "RUNNING"}.get(body.action, "RUNNING")
    async with get_session() as session:
        stmt = select(JobState).where(JobState.container_name == body.container_name)
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        if job:
            job.status = new_status
            job.last_seen = datetime.now(timezone.utc)
            await session.commit()

    return {"container": body.container_name, "action": body.action, "success": True}


# ---------------------------------------------------------------------------
# POST /api/v1/kill — hard-kill all active workers
# ---------------------------------------------------------------------------
@app.post("/api/v1/kill")
async def kill_all():
    """SIGKILL all RUNNING/PAUSED containers and mark all active jobs as KILLED."""
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]
    killable_statuses = ["RUNNING", "PAUSED"]

    async with get_session() as session:
        stmt = select(JobState).where(JobState.status.in_(active_statuses))
        result = await session.execute(stmt)
        jobs = result.scalars().all()

        if not jobs:
            return {"success": True, "killed_count": 0, "containers": []}

        target_id = jobs[0].target_id
        containers = []

        for job in jobs:
            containers.append(job.container_name)
            if job.status in killable_statuses:
                await worker_manager.kill_worker(job.container_name)
            job.status = "KILLED"
            job.last_seen = datetime.now(timezone.utc)

        await session.commit()

    await push_task(f"events:{target_id}", {
        "event": "KILL_ALL",
        "target_id": target_id,
        "killed_count": len(containers),
        "containers": containers,
    })

    return {"success": True, "killed_count": len(containers), "containers": containers}


# ---------------------------------------------------------------------------
# POST /api/v1/rerun — rerun target with specified playbook
# ---------------------------------------------------------------------------
@app.post("/api/v1/rerun")
async def rerun_target(body: RerunRequest):
    """Re-queue a target with the specified playbook. Preserves existing data."""
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == body.target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        active = (await session.execute(
            select(func.count(JobState.id)).where(
                JobState.target_id == body.target_id,
                JobState.status.in_(active_statuses),
            )
        )).scalar()
        if active > 0:
            raise HTTPException(status_code=409, detail="Active jobs exist. Kill them first.")

        playbook_config = None
        if body.playbook_name in BUILTIN_PLAYBOOKS:
            playbook_config = BUILTIN_PLAYBOOKS[body.playbook_name]
        else:
            custom = (await session.execute(
                select(CustomPlaybook).where(CustomPlaybook.name == body.playbook_name)
            )).scalar_one_or_none()
            if custom:
                from lib_webbh.playbooks import PlaybookConfig, StageConfig, ConcurrencyConfig
                playbook_config = PlaybookConfig(
                    name=custom.name,
                    description=custom.description or "",
                    stages=[StageConfig(**s) for s in (custom.stages or [])],
                    concurrency=ConcurrencyConfig(**(custom.concurrency or {})),
                )

        if not playbook_config:
            raise HTTPException(status_code=404, detail=f"Playbook '{body.playbook_name}' not found")

        profile_dir = SHARED_CONFIG / str(body.target_id)
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "playbook.json").write_text(
            json.dumps(playbook_config.to_dict(), indent=2)
        )

        target.last_playbook = body.playbook_name
        await session.commit()

    await push_task("recon_queue", {
        "target_id": body.target_id,
        "action": "rerun",
    })

    await push_task(f"events:{body.target_id}", {
        "event": "RERUN_STARTED",
        "target_id": body.target_id,
        "playbook_name": body.playbook_name,
    })

    return {"success": True, "target_id": body.target_id, "playbook_name": body.playbook_name}


# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/clean-slate — wipe all target data
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/clean-slate")
async def clean_slate(target_id: int):
    """Delete all discovered data for a target. Preserves target, config, bounties."""
    from sqlalchemy import delete
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        active = (await session.execute(
            select(func.count(JobState.id)).where(
                JobState.target_id == target_id,
                JobState.status.in_(active_statuses),
            )
        )).scalar()
        if active > 0:
            raise HTTPException(status_code=409, detail="Active jobs exist. Kill them first.")

        # Delete in dependency order — child tables first.
        # BountySubmission has a non-nullable FK to Vulnerability, so we must
        # preserve vulns referenced by bounties (and the bounties themselves).
        asset_ids = select(Asset.id).where(Asset.target_id == target_id)

        bounty_vuln_ids = select(BountySubmission.vulnerability_id).where(
            BountySubmission.target_id == target_id
        )

        # Delete vulns NOT referenced by bounties
        await session.execute(
            delete(Vulnerability).where(
                Vulnerability.target_id == target_id,
                Vulnerability.id.notin_(bounty_vuln_ids),
            )
        )

        await session.execute(delete(Parameter).where(Parameter.asset_id.in_(asset_ids)))
        await session.execute(delete(ApiSchema).where(ApiSchema.target_id == target_id))
        await session.execute(delete(MobileApp).where(MobileApp.target_id == target_id))
        await session.execute(delete(Location).where(Location.asset_id.in_(asset_ids)))
        await session.execute(delete(Observation).where(Observation.asset_id.in_(asset_ids)))
        await session.execute(delete(Identity).where(Identity.target_id == target_id))
        await session.execute(delete(CloudAsset).where(CloudAsset.target_id == target_id))
        await session.execute(delete(AssetSnapshot).where(AssetSnapshot.target_id == target_id))
        await session.execute(delete(ScopeViolation).where(ScopeViolation.target_id == target_id))
        await session.execute(delete(Alert).where(Alert.target_id == target_id))
        await session.execute(delete(JobState).where(JobState.target_id == target_id))
        await session.execute(delete(Asset).where(Asset.target_id == target_id))

        await session.commit()

    await push_task(f"events:{target_id}", {
        "event": "CLEAN_SLATE",
        "target_id": target_id,
    })

    # Brief delay so SSE consumers receive the CLEAN_SLATE event before
    # the stream is destroyed, then purge the Redis event stream.
    await asyncio.sleep(0.5)
    r = get_redis()
    await r.delete(f"events:{target_id}")

    return {"success": True, "target_id": target_id}


# ---------------------------------------------------------------------------
# DELETE /api/v1/targets/{target_id} — permanently delete a target
# ---------------------------------------------------------------------------
@app.delete("/api/v1/targets/{target_id}")
async def delete_target(target_id: int):
    """Permanently delete a target and all associated data."""
    from sqlalchemy import delete as sa_delete
    import shutil

    # 1. Load target with relationships for ORM cascade delete
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

    # 2. Auto-kill any running/paused containers for this target
    containers = await worker_manager.list_webbh_containers()
    for c in containers:
        if c.name.endswith(f"-t{target_id}") and c.status in ("running", "paused"):
            await worker_manager.kill_worker(c.name)

    # 3. Delete all child rows in dependency order, then the target.
    #    No FK has ON DELETE CASCADE, so we must do this explicitly.
    async with get_session() as session:
        asset_ids = select(Asset.id).where(Asset.target_id == target_id)

        # Grandchildren (FK → assets)
        await session.execute(sa_delete(Parameter).where(Parameter.asset_id.in_(asset_ids)))
        await session.execute(sa_delete(Location).where(Location.asset_id.in_(asset_ids)))
        await session.execute(sa_delete(Observation).where(Observation.asset_id.in_(asset_ids)))

        # Children with FK → vulnerabilities
        await session.execute(sa_delete(BountySubmission).where(BountySubmission.target_id == target_id))
        await session.execute(sa_delete(Alert).where(Alert.target_id == target_id))

        # Children with FK → assets (nullable) or FK → targets
        await session.execute(sa_delete(Vulnerability).where(Vulnerability.target_id == target_id))
        await session.execute(sa_delete(ApiSchema).where(ApiSchema.target_id == target_id))
        await session.execute(sa_delete(MobileApp).where(MobileApp.target_id == target_id))
        await session.execute(sa_delete(Asset).where(Asset.target_id == target_id))

        # Direct children of target
        await session.execute(sa_delete(Identity).where(Identity.target_id == target_id))
        await session.execute(sa_delete(CloudAsset).where(CloudAsset.target_id == target_id))
        await session.execute(sa_delete(AssetSnapshot).where(AssetSnapshot.target_id == target_id))
        await session.execute(sa_delete(JobState).where(JobState.target_id == target_id))
        await session.execute(sa_delete(ScheduledScan).where(ScheduledScan.target_id == target_id))
        await session.execute(sa_delete(ScopeViolation).where(ScopeViolation.target_id == target_id))

        # Finally the target itself
        await session.execute(sa_delete(Target).where(Target.id == target_id))
        await session.commit()

    # 4. Purge Redis event stream
    r = get_redis()
    await r.delete(f"events:{target_id}")

    # 5. Remove config directory
    config_dir = SHARED_CONFIG / str(target_id)
    if config_dir.exists():
        shutil.rmtree(config_dir)

    # 6. Remove reports directory
    reports_dir = SHARED_REPORTS / str(target_id)
    if reports_dir.exists():
        shutil.rmtree(reports_dir)

    logger.info("Target deleted", extra={"target_id": target_id})
    return {"success": True, "target_id": target_id}


# ---------------------------------------------------------------------------
# GET /api/v1/search — Global search across assets & vulnerabilities
# ---------------------------------------------------------------------------
@app.get("/api/v1/search")
async def search(
    target_id: int = Query(...),
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(default=50, le=200),
):
    """Search across assets and vulnerabilities for a given target."""
    results: list[dict] = []
    async with get_session() as session:
        # Search assets
        asset_stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_value.ilike(f"%{q}%"),
        ).limit(limit)
        for a in (await session.execute(asset_stmt)).scalars():
            results.append({"type": "asset", "id": a.id, "value": a.asset_value, "subtype": a.asset_type})

        # Search vulnerabilities
        vuln_stmt = select(Vulnerability).where(
            Vulnerability.target_id == target_id,
            or_(
                Vulnerability.title.ilike(f"%{q}%"),
                Vulnerability.description.ilike(f"%{q}%"),
            ),
        ).limit(limit)
        for v in (await session.execute(vuln_stmt)).scalars():
            results.append({"type": "vulnerability", "id": v.id, "value": v.title, "subtype": v.severity})

    return {"query": q, "results": results[:limit]}


# ---------------------------------------------------------------------------
# GET /api/v1/stream/{target_id} — SSE
# ---------------------------------------------------------------------------
@app.get("/api/v1/stream/{target_id}")
async def stream_events(target_id: int, request: Request):
    """Server-Sent Events stream for a specific target.

    Publishes events: TOOL_PROGRESS, NEW_ASSET, CRITICAL_ALERT, WORKER_SPAWNED.
    Events are pushed to the ``events:{target_id}`` Redis stream by the event
    engine and consumed here.

    Supports ``Last-Event-ID`` header for reconnection replay: on reconnect the
    client sends the last received event ID and the server replays any missed
    messages via XRANGE before switching to the live XREADGROUP loop.
    """
    queue = f"events:{target_id}"
    group = "sse_consumers"
    consumer = f"sse-{uuid4().hex}"

    redis = get_redis()
    try:
        await redis.xgroup_create(queue, group, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    last_event_id = request.headers.get("Last-Event-ID")

    async def _generate():
        connected_sse_clients.inc()
        try:
            # Replay missed messages if Last-Event-ID provided
            if last_event_id:
                messages = await redis.xrange(queue, min=last_event_id, count=500)
                for msg_id, data in messages:
                    if msg_id == last_event_id:
                        continue  # Skip the one already received
                    payload = json.loads(data.get("payload", "{}"))
                    event_type = payload.get("event", "message")
                    yield {"event": event_type, "data": json.dumps(payload), "id": msg_id}

            # Continue with live stream
            while True:
                if await request.is_disconnected():
                    break
                messages = await redis.xreadgroup(
                    groupname=group,
                    consumername=consumer,
                    streams={queue: ">"},
                    count=10,
                    block=2000,
                )
                for _, entries in messages:
                    for msg_id, data in entries:
                        payload = json.loads(data.get("payload", "{}"))
                        event_type = payload.get("event", "message")
                        yield {"event": event_type, "data": json.dumps(payload), "id": msg_id}
                        await redis.xack(queue, group, msg_id)
        except asyncio.CancelledError:
            pass
        finally:
            connected_sse_clients.dec()
            # Release any claimed-but-unacked messages
            try:
                await redis.xautoclaim(queue, group, consumer, min_idle_time=0)
            except Exception:
                pass

    return EventSourceResponse(_generate())


# ---------------------------------------------------------------------------
# GET /api/v1/targets — list all targets
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets")
async def list_targets():
    STATUS_PRIORITY = {
        "running": 6,
        "queued": 5,
        "paused": 4,
        "completed": 3,
        "failed": 2,
        "killed": 1,
        "stopped": 1,
    }

    async with get_session() as session:
        # 1. Fetch all targets
        stmt = select(Target).order_by(Target.created_at.desc())
        result = await session.execute(stmt)
        targets = result.scalars().all()

        target_ids = [t.id for t in targets]

        # Initialise lookup dicts
        asset_counts: dict[int, int] = {}
        vuln_counts: dict[int, int] = {}
        status_map: dict[int, str] = {}
        activity_map: dict[int, datetime | None] = {}

        if target_ids:
            # 2. Asset counts grouped by target_id
            asset_stmt = (
                select(Asset.target_id, func.count(Asset.id))
                .where(Asset.target_id.in_(target_ids))
                .group_by(Asset.target_id)
            )
            asset_rows = await session.execute(asset_stmt)
            for tid, cnt in asset_rows:
                asset_counts[tid] = cnt

            # 3. Vulnerability counts grouped by target_id
            vuln_stmt = (
                select(Vulnerability.target_id, func.count(Vulnerability.id))
                .where(Vulnerability.target_id.in_(target_ids))
                .group_by(Vulnerability.target_id)
            )
            vuln_rows = await session.execute(vuln_stmt)
            for tid, cnt in vuln_rows:
                vuln_counts[tid] = cnt

            # 4. Job statuses grouped by target_id and status, with max updated_at
            job_stmt = (
                select(
                    JobState.target_id,
                    JobState.status,
                    func.max(JobState.updated_at).label("last_activity"),
                )
                .where(JobState.target_id.in_(target_ids))
                .group_by(JobState.target_id, JobState.status)
            )
            job_rows = await session.execute(job_stmt)
            for tid, status, last_act in job_rows:
                status_lower = status.lower() if status else "idle"
                priority = STATUS_PRIORITY.get(status_lower, 0)
                # Pick highest priority status per target
                current_status = status_map.get(tid)
                current_priority = STATUS_PRIORITY.get(current_status, -1) if current_status else -1
                if priority > current_priority:
                    status_map[tid] = status_lower
                # Track max last_activity across all statuses
                if last_act is not None:
                    existing = activity_map.get(tid)
                    if existing is None or last_act > existing:
                        activity_map[tid] = last_act

    return {
        "targets": [
            {
                "id": t.id,
                "company_name": t.company_name,
                "base_domain": t.base_domain,
                "target_profile": t.target_profile,
                "last_playbook": t.last_playbook,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                "asset_count": asset_counts.get(t.id, 0),
                "vuln_count": vuln_counts.get(t.id, 0),
                "status": status_map.get(t.id, "idle"),
                "last_activity": (
                    activity_map[t.id].isoformat()
                    if activity_map.get(t.id) is not None
                    else (t.updated_at.isoformat() if t.updated_at else None)
                ),
            }
            for t in targets
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/assets — list assets for a target (with locations)
# ---------------------------------------------------------------------------
@app.get("/api/v1/assets")
async def list_assets(target_id: int = Query(..., description="Target ID to filter assets")):
    async with get_session() as session:
        stmt = (
            select(Asset)
            .where(Asset.target_id == target_id)
            .options(selectinload(Asset.locations))
            .order_by(Asset.created_at.desc())
        )
        result = await session.execute(stmt)
        assets = result.scalars().all()

    return {
        "assets": [
            {
                "id": a.id,
                "target_id": a.target_id,
                "asset_type": a.asset_type,
                "asset_value": a.asset_value,
                "source_tool": a.source_tool,
                "tech": a.tech,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                "locations": [
                    {
                        "id": loc.id,
                        "port": loc.port,
                        "protocol": loc.protocol,
                        "service": loc.service,
                        "state": loc.state,
                    }
                    for loc in a.locations
                ],
            }
            for a in assets
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/vulnerabilities — list vulnerabilities for a target
# ---------------------------------------------------------------------------
@app.get("/api/v1/vulnerabilities")
async def list_vulnerabilities(
    target_id: int = Query(..., description="Target ID to filter vulnerabilities"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
):
    async with get_session() as session:
        stmt = (
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset))
        )
        if severity is not None:
            stmt = stmt.where(Vulnerability.severity == severity)
        result = await session.execute(stmt)
        vulns = result.scalars().all()

    return {
        "vulnerabilities": [
            {
                "id": v.id,
                "target_id": v.target_id,
                "asset_id": v.asset_id,
                "asset_value": v.asset.asset_value if v.asset else None,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "poc": v.poc,
                "source_tool": v.source_tool,
                "created_at": v.created_at.isoformat() if v.created_at else None,
                "updated_at": v.updated_at.isoformat() if v.updated_at else None,
            }
            for v in vulns
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/cloud_assets — list cloud assets for a target
# ---------------------------------------------------------------------------
@app.get("/api/v1/cloud_assets")
async def list_cloud_assets(
    target_id: int = Query(..., description="Target ID to filter cloud assets"),
):
    async with get_session() as session:
        stmt = (
            select(CloudAsset)
            .where(CloudAsset.target_id == target_id)
        )
        result = await session.execute(stmt)
        cloud_assets = result.scalars().all()

    return {
        "cloud_assets": [
            {
                "id": ca.id,
                "target_id": ca.target_id,
                "provider": ca.provider,
                "asset_type": ca.asset_type,
                "url": ca.url,
                "is_public": ca.is_public,
                "findings": ca.findings,
                "created_at": ca.created_at.isoformat() if ca.created_at else None,
                "updated_at": ca.updated_at.isoformat() if ca.updated_at else None,
            }
            for ca in cloud_assets
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/alerts — list alerts for a target
# ---------------------------------------------------------------------------
@app.get("/api/v1/alerts")
async def list_alerts(
    target_id: int = Query(..., description="Target ID to filter alerts"),
    is_read: Optional[bool] = Query(None, description="Filter by read status"),
):
    async with get_session() as session:
        stmt = (
            select(Alert)
            .where(Alert.target_id == target_id)
            .order_by(Alert.created_at.desc())
        )
        if is_read is not None:
            stmt = stmt.where(Alert.is_read == is_read)
        result = await session.execute(stmt)
        alerts = result.scalars().all()

    return {
        "alerts": [
            {
                "id": a.id,
                "target_id": a.target_id,
                "vulnerability_id": a.vulnerability_id,
                "alert_type": a.alert_type,
                "message": a.message,
                "is_read": a.is_read,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }


# ---------------------------------------------------------------------------
# PATCH /api/v1/alerts/{alert_id} — update alert read status
# ---------------------------------------------------------------------------
@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert(alert_id: int, body: AlertUpdate):
    async with get_session() as session:
        stmt = select(Alert).where(Alert.id == alert_id)
        result = await session.execute(stmt)
        alert = result.scalar_one_or_none()
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.is_read = body.is_read
        await session.commit()
        await session.refresh(alert)

    return {"id": alert.id, "is_read": alert.is_read}


# ---------------------------------------------------------------------------
# PATCH /api/v1/targets/{target_id} — update target profile
# ---------------------------------------------------------------------------
@app.patch("/api/v1/targets/{target_id}")
async def update_target_profile(target_id: int, body: TargetProfileUpdate):
    async with get_session() as session:
        result = await session.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        profile = target.target_profile or {}
        if body.custom_headers is not None:
            profile["custom_headers"] = body.custom_headers
        if body.rate_limits is not None:
            profile["rate_limits"] = body.rate_limits
        target.target_profile = profile
        attributes.flag_modified(target, "target_profile")
        await session.commit()
        await session.refresh(target)

    # Rewrite config files
    _generate_tool_configs(target_id, target.target_profile or {})

    return {
        "target_id": target_id,
        "target_profile": target.target_profile,
    }


# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/reports — trigger report generation
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/reports", status_code=201)
async def create_report(target_id: int, body: ReportCreate):
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        has_vulns = (await session.execute(
            select(Vulnerability.id).where(Vulnerability.target_id == target_id).limit(1)
        )).scalar_one_or_none()
        if has_vulns is None:
            raise HTTPException(status_code=400, detail="No vulnerabilities found for this target")

    msg_id = await push_task("report_queue", {
        "target_id": target_id,
        "formats": body.formats,
        "platform": body.platform,
    })

    logger.info("Report generation queued", extra={"target_id": target_id, "formats": body.formats})

    return {"job_id": msg_id, "status": "queued", "formats": body.formats}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/reports — list generated reports
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/reports")
async def list_reports(target_id: int):
    report_dir = SHARED_REPORTS / str(target_id)
    if not report_dir.is_dir():
        return {"reports": []}

    reports = []
    for f in sorted(report_dir.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            stat = f.stat()
            reports.append({
                "filename": f.name,
                "format": "pdf" if f.suffix == ".pdf" else "markdown",
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            })

    return {"reports": reports}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/reports/{filename} — download a report
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/reports/{filename}")
async def download_report(target_id: int, filename: str):
    # Prevent path traversal
    filepath = (SHARED_REPORTS / str(target_id) / filename).resolve()
    base_dir = (SHARED_REPORTS / str(target_id)).resolve()
    if not str(filepath).startswith(str(base_dir)):
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = "application/pdf" if filepath.suffix == ".pdf" else "text/markdown"
    return FileResponse(
        path=str(filepath),
        media_type=media_type,
        filename=filename,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/rescan — snapshot & queue rescan
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/rescan", status_code=201)
async def trigger_rescan(target_id: int):
    """Snapshot current assets and queue a rescan for delta detection."""
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        max_scan = (await session.execute(
            select(func.coalesce(func.max(AssetSnapshot.scan_number), 0))
            .where(AssetSnapshot.target_id == target_id)
        )).scalar()
        next_scan = max_scan + 1

        assets = (await session.execute(
            select(Asset).where(Asset.target_id == target_id)
        )).scalars().all()
        asset_hashes = {a.asset_value: f"{a.asset_type}:{a.source_tool}" for a in assets}

        snapshot = AssetSnapshot(
            target_id=target_id, scan_number=next_scan,
            asset_count=len(assets), asset_hashes=asset_hashes,
        )
        session.add(snapshot)
        await session.commit()

    await push_task("recon_queue", {
        "target_id": target_id, "rescan": True, "snapshot_scan_number": next_scan,
    })
    scans_triggered.labels(trigger_type="rescan").inc()
    return {"target_id": target_id, "status": "queued", "scan_number": next_scan}


# ---------------------------------------------------------------------------
# GET /api/v1/vulnerabilities/{vuln_id}/draft — draft report for platform
# ---------------------------------------------------------------------------
@app.get("/api/v1/vulnerabilities/{vuln_id}/draft")
async def draft_vuln_report(
    vuln_id: int,
    platform: str = Query(default="hackerone", description="hackerone or bugcrowd"),
):
    from lib_webbh.report_templates import render_vuln_report, Platform
    platform_enum = Platform.HACKERONE if platform == "hackerone" else Platform.BUGCROWD

    async with get_session() as session:
        vuln = (await session.execute(
            select(Vulnerability).where(Vulnerability.id == vuln_id)
            .options(selectinload(Vulnerability.asset))
        )).scalar_one_or_none()
        if vuln is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        vuln_dict = {
            "title": vuln.title, "severity": vuln.severity,
            "asset_value": vuln.asset.asset_value if vuln.asset else "N/A",
            "description": vuln.description, "poc": vuln.poc,
            "source_tool": vuln.source_tool, "cvss_score": vuln.cvss_score,
        }
    draft = render_vuln_report(vuln_dict, platform_enum)
    return {"vuln_id": vuln_id, "platform": platform, "draft": draft}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/graph — attack graph
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/graph")
async def get_attack_graph(target_id: int):
    nodes, edges = [], []
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        nodes.append({"id": f"target-{target.id}", "label": target.base_domain, "type": "target"})

        assets = (await session.execute(
            select(Asset).where(Asset.target_id == target_id)
            .options(selectinload(Asset.locations))
        )).scalars().all()
        for a in assets:
            node_id = f"asset-{a.id}"
            nodes.append({"id": node_id, "label": a.asset_value, "type": a.asset_type})
            edges.append({"source": f"target-{target.id}", "target": node_id})
            for loc in a.locations:
                loc_id = f"loc-{loc.id}"
                nodes.append({"id": loc_id, "label": f":{loc.port}/{loc.service or ''}", "type": "port"})
                edges.append({"source": node_id, "target": loc_id})

        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
        )).scalars().all()
        for v in vulns:
            vuln_id = f"vuln-{v.id}"
            nodes.append({"id": vuln_id, "label": v.title, "type": "vulnerability", "severity": v.severity})
            if v.asset_id:
                edges.append({"source": f"asset-{v.asset_id}", "target": vuln_id})
            else:
                edges.append({"source": f"target-{target.id}", "target": vuln_id})
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/attack-paths — exploitable vuln chains
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/attack-paths")
async def get_attack_paths(target_id: int):
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset))
        )).scalars().all()

        paths = []
        asset_vulns: dict[int, list] = {}
        for v in vulns:
            if v.asset_id:
                asset_vulns.setdefault(v.asset_id, []).append(v)

        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        path_id = 0
        for asset_id, avulns in asset_vulns.items():
            if len(avulns) < 2:
                continue
            sorted_vulns = sorted(avulns, key=lambda v: sev_order.get(v.severity, 0), reverse=True)
            path_id += 1
            steps = []
            for v in sorted_vulns:
                steps.append({
                    "vuln_id": v.id, "title": v.title, "severity": v.severity,
                    "asset_id": v.asset_id,
                    "asset_value": v.asset.asset_value if v.asset else None,
                })
            paths.append({
                "id": path_id, "severity": sorted_vulns[0].severity,
                "steps": steps,
                "description": f"Chain of {len(steps)} vulnerabilities on {steps[0]['asset_value'] or 'unknown'}",
            })
    return {"target_id": target_id, "paths": paths}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/execution — pipeline execution state
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/execution")
async def get_execution_state(target_id: int):
    from lib_webbh.playbooks import _ALL_RECON_STAGES

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        jobs = (await session.execute(
            select(JobState).where(JobState.target_id == target_id)
            .order_by(JobState.last_seen.desc())
        )).scalars().all()

    stages = []
    for stage_name in _ALL_RECON_STAGES:
        matching_jobs = [j for j in jobs if j.current_phase and stage_name in j.current_phase]
        if matching_jobs:
            job = matching_jobs[0]
            stages.append({
                "name": stage_name, "status": job.status.lower(),
                "tool": job.last_tool_executed,
                "started_at": job.created_at.isoformat() if job.created_at else None,
                "last_seen": job.last_seen.isoformat() if job.last_seen else None,
            })
        else:
            stages.append({"name": stage_name, "status": "pending", "tool": None, "started_at": None, "last_seen": None})

    return {"target_id": target_id, "playbook": target.last_playbook or "wide_recon", "stages": stages}


# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/apply-playbook — apply a playbook
# ---------------------------------------------------------------------------
class ApplyPlaybookRequest(BaseModel):
    playbook_name: str


@app.post("/api/v1/targets/{target_id}/apply-playbook")
async def apply_playbook(target_id: int, body: ApplyPlaybookRequest):
    from lib_webbh.playbooks import get_playbook

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")
        playbook = get_playbook(body.playbook_name)
        target.last_playbook = body.playbook_name
        await session.flush()

    config_dir = f"shared/config/{target_id}"
    os.makedirs(config_dir, exist_ok=True)
    with open(f"{config_dir}/playbook.json", "w") as f:
        json.dump(playbook.to_dict(), f, indent=2)

    return {"target_id": target_id, "playbook_name": body.playbook_name, "applied": True}


# ---------------------------------------------------------------------------
# GET /api/v1/assets/{asset_id}/locations — locations for an asset
# ---------------------------------------------------------------------------
@app.get("/api/v1/assets/{asset_id}/locations")
async def get_asset_locations(asset_id: int):
    async with get_session() as session:
        locs = (await session.execute(
            select(Location).where(Location.asset_id == asset_id)
        )).scalars().all()
    return {"asset_id": asset_id, "locations": [
        {"id": l.id, "port": l.port, "protocol": l.protocol, "service": l.service, "state": l.state}
        for l in locs
    ]}


# ---------------------------------------------------------------------------
# GET /api/v1/assets/{asset_id}/vulnerabilities — vulns for an asset
# ---------------------------------------------------------------------------
@app.get("/api/v1/assets/{asset_id}/vulnerabilities")
async def get_asset_vulns(asset_id: int):
    async with get_session() as session:
        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.asset_id == asset_id)
        )).scalars().all()
    return {"asset_id": asset_id, "vulnerabilities": [
        {"id": v.id, "severity": v.severity, "title": v.title, "description": v.description, "source_tool": v.source_tool}
        for v in vulns
    ]}


# ---------------------------------------------------------------------------
# GET /api/v1/assets/{asset_id}/cloud — cloud assets for an asset's target
# ---------------------------------------------------------------------------
@app.get("/api/v1/assets/{asset_id}/cloud")
async def get_asset_cloud(asset_id: int):
    async with get_session() as session:
        asset = (await session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        clouds = (await session.execute(
            select(CloudAsset).where(CloudAsset.target_id == asset.target_id)
        )).scalars().all()
    return {"asset_id": asset_id, "cloud_assets": [
        {"id": c.id, "provider": c.provider, "asset_type": c.asset_type, "url": c.url, "is_public": c.is_public}
        for c in clouds
    ]}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/correlations — correlated vuln groups
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/correlations")
async def get_correlations(target_id: int):
    from lib_webbh.correlation import correlate_findings

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset))
        )).scalars().all()

    vuln_dicts = [
        {
            "id": v.id, "title": v.title, "severity": v.severity,
            "asset_id": v.asset_id,
            "asset_value": v.asset.asset_value if v.asset else None,
            "source_tool": v.source_tool, "cvss_score": v.cvss_score,
        }
        for v in vulns
    ]
    groups = correlate_findings(vuln_dicts)
    return {
        "target_id": target_id,
        "groups": [
            {
                "shared_assets": g.shared_assets,
                "severity": g.composite_severity,
                "count": len(g.vuln_ids),
                "vuln_ids": g.vuln_ids,
                "chain_description": g.chain_description,
            }
            for g in groups
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/queue_health — queue depth health status
# ---------------------------------------------------------------------------
@app.get("/api/v1/queue_health")
async def get_queue_health():
    from lib_webbh.messaging import get_pending
    from lib_webbh.queue_monitor import assess_queue_health

    queues = ["recon_queue", "fuzzing_queue", "webapp_queue", "cloud_queue", "api_queue"]
    results = {}
    for q in queues:
        try:
            info = await get_pending(q, f"{q.replace('_queue', '')}_group")
            pending = info.get("pending", 0)
        except Exception:
            pending = 0
        health = assess_queue_health(pending)
        results[q] = {"pending": pending, "health": health.value}
    return {"queues": results}


# ---------------------------------------------------------------------------
# POST /api/v1/bounties — create a bounty submission
# ---------------------------------------------------------------------------
@app.post("/api/v1/bounties", status_code=201)
async def create_bounty(body: BountyCreate):
    async with get_session() as session:
        # Verify vulnerability exists
        vuln = (await session.execute(
            select(Vulnerability).where(Vulnerability.id == body.vulnerability_id)
        )).scalar_one_or_none()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        submission = BountySubmission(
            target_id=body.target_id,
            vulnerability_id=body.vulnerability_id,
            platform=body.platform,
            status=body.status,
            submission_url=body.submission_url,
            expected_payout=body.expected_payout,
            notes=body.notes,
        )
        session.add(submission)
        await session.commit()
        await session.refresh(submission)
        bounties_submitted.labels(platform=body.platform).inc()
        return {
            "id": submission.id,
            "target_id": submission.target_id,
            "vulnerability_id": submission.vulnerability_id,
            "platform": submission.platform,
            "status": submission.status,
            "submission_url": submission.submission_url,
            "expected_payout": submission.expected_payout,
            "actual_payout": submission.actual_payout,
            "notes": submission.notes,
        }


# ---------------------------------------------------------------------------
# GET /api/v1/bounties — list bounty submissions
# ---------------------------------------------------------------------------
@app.get("/api/v1/bounties")
async def list_bounties(
    target_id: Optional[int] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    async with get_session() as session:
        stmt = select(BountySubmission)
        if target_id is not None:
            stmt = stmt.where(BountySubmission.target_id == target_id)
        if status is not None:
            stmt = stmt.where(BountySubmission.status == status)
        stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": r.id,
                "target_id": r.target_id,
                "vulnerability_id": r.vulnerability_id,
                "platform": r.platform,
                "status": r.status,
                "submission_url": r.submission_url,
                "expected_payout": r.expected_payout,
                "actual_payout": r.actual_payout,
                "notes": r.notes,
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# PATCH /api/v1/bounties/{bounty_id} — update bounty submission
# ---------------------------------------------------------------------------
@app.patch("/api/v1/bounties/{bounty_id}")
async def update_bounty(bounty_id: int, body: BountyUpdate):
    async with get_session() as session:
        submission = (await session.execute(
            select(BountySubmission).where(BountySubmission.id == bounty_id)
        )).scalar_one_or_none()
        if not submission:
            raise HTTPException(status_code=404, detail="Bounty submission not found")
        updates = body.model_dump(exclude_none=True)
        for key, value in updates.items():
            setattr(submission, key, value)
        await session.commit()
        await session.refresh(submission)
        return {
            "id": submission.id,
            "target_id": submission.target_id,
            "vulnerability_id": submission.vulnerability_id,
            "platform": submission.platform,
            "status": submission.status,
            "submission_url": submission.submission_url,
            "expected_payout": submission.expected_payout,
            "actual_payout": submission.actual_payout,
            "notes": submission.notes,
        }


# ---------------------------------------------------------------------------
# GET /api/v1/bounties/stats — ROI stats
# ---------------------------------------------------------------------------
@app.get("/api/v1/bounties/stats")
async def bounty_stats(target_id: Optional[int] = Query(default=None)):
    async with get_session() as session:
        stmt = select(BountySubmission)
        if target_id is not None:
            stmt = stmt.where(BountySubmission.target_id == target_id)
        rows = (await session.execute(stmt)).scalars().all()

        total_submitted = len(rows)
        total_accepted = sum(1 for r in rows if r.status == "accepted")
        total_paid = sum(1 for r in rows if r.actual_payout and r.actual_payout > 0)
        total_payout = sum(r.actual_payout for r in rows if r.actual_payout)

        by_platform: dict[str, int] = {}
        by_target: dict[int, float] = {}
        for r in rows:
            by_platform[r.platform] = by_platform.get(r.platform, 0) + 1
            if r.actual_payout:
                by_target[r.target_id] = by_target.get(r.target_id, 0.0) + r.actual_payout

        return {
            "total_submitted": total_submitted,
            "total_accepted": total_accepted,
            "total_paid": total_paid,
            "total_payout": total_payout,
            "by_platform": by_platform,
            "by_target": by_target,
        }


# ---------------------------------------------------------------------------
# POST /api/v1/schedules — create a scheduled scan
# ---------------------------------------------------------------------------
@app.post("/api/v1/schedules", status_code=201)
async def create_schedule(body: ScheduleCreate):
    if not is_valid_cron(body.cron_expression):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == body.target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        computed_next = next_run(body.cron_expression)
        schedule = ScheduledScan(
            target_id=body.target_id,
            cron_expression=body.cron_expression,
            playbook=body.playbook,
            enabled=True,
            next_run_at=computed_next,
        )
        session.add(schedule)
        await session.commit()
        await session.refresh(schedule)

    return {
        "id": schedule.id,
        "target_id": schedule.target_id,
        "cron_expression": schedule.cron_expression,
        "playbook": schedule.playbook,
        "enabled": schedule.enabled,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/schedules — list schedules
# ---------------------------------------------------------------------------
@app.get("/api/v1/schedules")
async def list_schedules(target_id: Optional[int] = Query(default=None)):
    async with get_session() as session:
        stmt = select(ScheduledScan)
        if target_id is not None:
            stmt = stmt.where(ScheduledScan.target_id == target_id)
        result = await session.execute(stmt)
        schedules = result.scalars().all()

    return [
        {
            "id": s.id,
            "target_id": s.target_id,
            "cron_expression": s.cron_expression,
            "playbook": s.playbook,
            "enabled": s.enabled,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        }
        for s in schedules
    ]


# ---------------------------------------------------------------------------
# PATCH /api/v1/schedules/{schedule_id} — update schedule
# ---------------------------------------------------------------------------
@app.patch("/api/v1/schedules/{schedule_id}")
async def update_schedule(schedule_id: int, body: ScheduleUpdate):
    async with get_session() as session:
        schedule = (await session.execute(
            select(ScheduledScan).where(ScheduledScan.id == schedule_id)
        )).scalar_one_or_none()
        if schedule is None:
            raise HTTPException(status_code=404, detail="Schedule not found")

        if body.cron_expression is not None:
            if not is_valid_cron(body.cron_expression):
                raise HTTPException(status_code=400, detail="Invalid cron expression")
            schedule.cron_expression = body.cron_expression
            schedule.next_run_at = next_run(body.cron_expression)

        if body.enabled is not None:
            schedule.enabled = body.enabled

        if body.playbook is not None:
            schedule.playbook = body.playbook

        await session.commit()
        await session.refresh(schedule)

    return {
        "id": schedule.id,
        "target_id": schedule.target_id,
        "cron_expression": schedule.cron_expression,
        "playbook": schedule.playbook,
        "enabled": schedule.enabled,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
    }


# ---------------------------------------------------------------------------
# DELETE /api/v1/schedules/{schedule_id} — delete schedule
# ---------------------------------------------------------------------------
@app.delete("/api/v1/schedules/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: int):
    async with get_session() as session:
        schedule = (await session.execute(
            select(ScheduledScan).where(ScheduledScan.id == schedule_id)
        )).scalar_one_or_none()
        if schedule is None:
            raise HTTPException(status_code=404, detail="Schedule not found")
        await session.delete(schedule)
        await session.commit()

    return None


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/export — export findings
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/export")
async def export_findings(
    target_id: int,
    format: str = Query(default="json", description="json, csv, or markdown"),
    severity: Optional[str] = Query(default=None),
):
    async with get_session() as session:
        stmt = (
            select(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .where(Vulnerability.target_id == target_id)
            .order_by(Vulnerability.created_at.desc())
        )
        if severity:
            stmt = stmt.where(Vulnerability.severity == severity)
        result = await session.execute(stmt)
        vulns = result.scalars().all()

    rows = []
    for v in vulns:
        rows.append({
            "id": v.id,
            "severity": v.severity,
            "title": v.title,
            "asset": v.asset.asset_value if v.asset else "",
            "source_tool": v.source_tool or "",
            "cvss": v.cvss_score,
            "description": v.description or "",
            "created_at": v.created_at.isoformat() if v.created_at else "",
        })

    if format == "csv":
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=findings_target_{target_id}.csv"},
        )
    elif format == "markdown":
        lines = [f"# Findings Export — Target {target_id}\n"]
        lines.append("| ID | Severity | Title | Asset | Tool | CVSS | Date |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in rows:
            lines.append(f"| {r['id']} | {r['severity']} | {r['title']} | {r['asset']} | {r['source_tool']} | {r['cvss'] or '-'} | {r['created_at'][:10] if r['created_at'] else '-'} |")
        md = "\n".join(lines)
        return StreamingResponse(
            iter([md]),
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=findings_target_{target_id}.md"},
        )
    else:
        return {"target_id": target_id, "count": len(rows), "vulnerabilities": rows}


# ---------------------------------------------------------------------------
# GET /api/v1/config/api_keys — check which intel API keys are set
# ---------------------------------------------------------------------------
@app.get("/api/v1/config/api_keys")
async def get_api_key_status():
    return {"keys": get_available_intel_sources()}


# ---------------------------------------------------------------------------
# PUT /api/v1/config/api_keys — update intel API keys at runtime
# ---------------------------------------------------------------------------
@app.put("/api/v1/config/api_keys")
async def update_api_keys(body: ApiKeyUpdate):
    env_lines: list[str] = []

    if body.shodan_api_key is not None:
        os.environ["SHODAN_API_KEY"] = body.shodan_api_key
        _intel_mod.SHODAN_API_KEY = body.shodan_api_key
        env_lines.append(f"SHODAN_API_KEY={body.shodan_api_key}")

    if body.securitytrails_api_key is not None:
        os.environ["SECURITYTRAILS_API_KEY"] = body.securitytrails_api_key
        _intel_mod.SECURITYTRAILS_API_KEY = body.securitytrails_api_key
        env_lines.append(f"SECURITYTRAILS_API_KEY={body.securitytrails_api_key}")

    # Persist to .env.intel file (best-effort — keys are already set in memory)
    if env_lines:
        try:
            env_file = SHARED_CONFIG / ".env.intel"
            env_file.parent.mkdir(parents=True, exist_ok=True)

            # Merge with existing content
            existing: dict[str, str] = {}
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        existing[k] = v
            for line in env_lines:
                k, v = line.split("=", 1)
                existing[k] = v
            env_file.write_text(
                "\n".join(f"{k}={v}" for k, v in existing.items()) + "\n"
            )
        except OSError as exc:
            logger.warning("could not persist api keys to disk", extra={"error": str(exc)})

    return {"keys": get_available_intel_sources()}


# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/enrich — run intel enrichment
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/enrich")
async def enrich_target(target_id: int):
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")
        domain = target.base_domain

    # Run enrichment from all available sources
    shodan_result = await enrich_shodan(domain)
    st_result = await enrich_securitytrails(domain)

    # Aggregate unique subdomains and IPs
    all_subdomains: list[str] = []
    all_ips: list[str] = []
    for r in (shodan_result, st_result):
        for s in r.subdomains:
            if s not in all_subdomains:
                all_subdomains.append(s)
        for ip in r.ips:
            if ip not in all_ips:
                all_ips.append(ip)

    # Insert into DB (skip duplicates via get-or-create)
    inserted_subdomains = 0
    inserted_ips = 0

    async with get_session() as session:
        for sub in all_subdomains:
            existing = (await session.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "subdomain",
                    Asset.asset_value == sub,
                )
            )).scalar_one_or_none()
            if existing is None:
                session.add(Asset(
                    target_id=target_id,
                    asset_type="subdomain",
                    asset_value=sub,
                    source_tool="intel_enrichment",
                ))
                inserted_subdomains += 1

        for ip in all_ips:
            existing = (await session.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "ip",
                    Asset.asset_value == ip,
                )
            )).scalar_one_or_none()
            if existing is None:
                session.add(Asset(
                    target_id=target_id,
                    asset_type="ip",
                    asset_value=ip,
                    source_tool="intel_enrichment",
                ))
                inserted_ips += 1

        await session.commit()

    return {
        "target_id": target_id,
        "domain": domain,
        "sources": {
            "shodan": {
                "subdomains": len(shodan_result.subdomains),
                "ips": len(shodan_result.ips),
                "ports": len(shodan_result.ports),
            },
            "securitytrails": {
                "subdomains": len(st_result.subdomains),
                "ips": len(st_result.ips),
            },
        },
        "total_subdomains": len(all_subdomains),
        "total_ips": len(all_ips),
        "inserted_subdomains": inserted_subdomains,
        "inserted_ips": inserted_ips,
    }


# ---------------------------------------------------------------------------
# Scope violation audit log
# ---------------------------------------------------------------------------
@app.get("/api/v1/scope_violations")
async def list_scope_violations(
    target_id: int = Query(...),
    limit: int = Query(default=100, le=500),
):
    async with get_session() as session:
        stmt = (
            select(ScopeViolation)
            .where(ScopeViolation.target_id == target_id)
            .order_by(ScopeViolation.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        violations = result.scalars().all()
    return {"violations": [
        {
            "id": v.id,
            "tool_name": v.tool_name,
            "input_value": v.input_value,
            "violation_type": v.violation_type,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
        for v in violations
    ]}


# ---------------------------------------------------------------------------
# Custom Playbook CRUD
# ---------------------------------------------------------------------------
@app.post("/api/v1/playbooks", status_code=201)
async def create_playbook(body: PlaybookCreate):
    async with get_session() as session:
        # Check for duplicate name (including built-in names)
        if body.name in BUILTIN_PLAYBOOKS:
            raise HTTPException(status_code=409, detail="Playbook name conflicts with a built-in playbook")

        existing = await session.execute(
            select(CustomPlaybook).where(CustomPlaybook.name == body.name)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Playbook with this name already exists")

        playbook = CustomPlaybook(
            name=body.name,
            description=body.description,
            stages=body.stages,
            concurrency=body.concurrency,
        )
        session.add(playbook)
        await session.commit()
        await session.refresh(playbook)

    return {
        "id": playbook.id,
        "name": playbook.name,
        "description": playbook.description,
        "stages": playbook.stages,
        "concurrency": playbook.concurrency,
        "builtin": False,
    }


@app.get("/api/v1/playbooks")
async def list_playbooks():
    results = []

    # Built-in playbooks
    for name, pb in BUILTIN_PLAYBOOKS.items():
        d = pb.to_dict()
        d["builtin"] = True
        results.append(d)

    # Custom playbooks from DB
    async with get_session() as session:
        rows = await session.execute(select(CustomPlaybook))
        for pb in rows.scalars().all():
            results.append({
                "id": pb.id,
                "name": pb.name,
                "description": pb.description,
                "stages": pb.stages,
                "concurrency": pb.concurrency,
                "builtin": False,
            })

    return results


@app.patch("/api/v1/playbooks/{playbook_id}")
async def update_playbook(playbook_id: int, body: PlaybookUpdate):
    async with get_session() as session:
        result = await session.execute(
            select(CustomPlaybook).where(CustomPlaybook.id == playbook_id)
        )
        playbook = result.scalar_one_or_none()
        if not playbook:
            raise HTTPException(status_code=404, detail="Playbook not found")

        if body.description is not None:
            playbook.description = body.description
        if body.stages is not None:
            playbook.stages = body.stages
        if body.concurrency is not None:
            playbook.concurrency = body.concurrency

        await session.commit()
        await session.refresh(playbook)

    return {
        "id": playbook.id,
        "name": playbook.name,
        "description": playbook.description,
        "stages": playbook.stages,
        "concurrency": playbook.concurrency,
        "builtin": False,
    }


@app.delete("/api/v1/playbooks/{playbook_id}", status_code=204)
async def delete_playbook(playbook_id: int):
    async with get_session() as session:
        result = await session.execute(
            select(CustomPlaybook).where(CustomPlaybook.id == playbook_id)
        )
        playbook = result.scalar_one_or_none()
        if not playbook:
            raise HTTPException(status_code=404, detail="Playbook not found")

        await session.delete(playbook)
        await session.commit()

    return None


# ---------------------------------------------------------------------------
# Config generation (called on target init)
# ---------------------------------------------------------------------------
def _generate_tool_configs(target_id: int, profile: dict) -> None:
    """Write tool-specific configs derived from the target profile."""
    config_dir = SHARED_CONFIG / str(target_id)
    config_dir.mkdir(parents=True, exist_ok=True)

    # Custom headers file (consumed by httpx-based workers)
    custom_headers = profile.get("custom_headers", {})
    (config_dir / "custom_headers.json").write_text(json.dumps(custom_headers, indent=2))

    # Rate-limit config
    rate_limits = profile.get("rate_limits", {})
    (config_dir / "rate_limits.json").write_text(json.dumps(rate_limits, indent=2))

    # Scope rules (consumed by ScopeManager in workers)
    scope_keys = ("in_scope_domains", "out_scope_domains", "in_scope_cidrs", "in_scope_regex")
    scope = {k: profile.get(k, []) for k in scope_keys}
    (config_dir / "scope.json").write_text(json.dumps(scope, indent=2))

    logger.info("Tool configs generated", extra={"target_id": target_id, "dir": str(config_dir)})


# ---------------------------------------------------------------------------
# Test seed endpoint -- inserts fixture data for e2e tests
# ---------------------------------------------------------------------------
ENABLE_TEST_SEED = os.environ.get("ENABLE_TEST_SEED", "").lower() == "true"


class TestSeedRequest(BaseModel):
    target_id: int = Field(..., gt=0)


class TestEmitEventRequest(BaseModel):
    target_id: int = Field(..., gt=0)
    event_data: dict = Field(...)


@app.post("/api/v1/test/seed")
async def test_seed(body: TestSeedRequest):
    """Insert fixture assets, vulns, cloud assets, and alerts for e2e tests.

    Guarded by ENABLE_TEST_SEED=true -- returns 404 in production.
    """
    if not ENABLE_TEST_SEED:
        raise HTTPException(status_code=404, detail="Not found")

    async with get_session() as session:
        # Verify target exists
        result = await session.execute(
            select(Target).where(Target.id == body.target_id)
        )
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # --- Assets ---
        assets_data = [
            {"asset_type": "subdomain", "asset_value": f"sub1.{target.base_domain}", "source_tool": "e2e-seed"},
            {"asset_type": "subdomain", "asset_value": f"sub2.{target.base_domain}", "source_tool": "e2e-seed"},
            {"asset_type": "subdomain", "asset_value": f"admin.{target.base_domain}", "source_tool": "e2e-seed"},
            {"asset_type": "ip", "asset_value": "10.0.0.1", "source_tool": "e2e-seed"},
            {"asset_type": "ip", "asset_value": "10.0.0.2", "source_tool": "e2e-seed"},
        ]
        asset_ids = []
        for ad in assets_data:
            asset = Asset(target_id=body.target_id, **ad)
            session.add(asset)
            await session.flush()
            asset_ids.append(asset.id)

        # --- Locations (on first asset) ---
        session.add(Location(asset_id=asset_ids[0], port=80, protocol="tcp", service="http", state="open"))
        session.add(Location(asset_id=asset_ids[0], port=443, protocol="tcp", service="https", state="open"))

        # --- Additional locations on other assets ---
        session.add(Location(asset_id=asset_ids[1], port=8080, protocol="tcp", service="http-alt", state="open"))
        session.add(Location(asset_id=asset_ids[3], port=22, protocol="tcp", service="ssh", state="open"))
        session.add(Location(asset_id=asset_ids[3], port=443, protocol="tcp", service="https", state="open"))

        # --- Vulnerabilities ---
        vulns_data = [
            {"severity": "critical", "title": "SQL Injection in login", "description": "Blind SQLi via id param", "source_tool": "e2e-seed"},
            {"severity": "medium", "title": "Reflected XSS in search", "description": "XSS via q parameter", "source_tool": "e2e-seed"},
            {"severity": "low", "title": "Information Disclosure", "description": "Server version in headers", "source_tool": "e2e-seed"},
        ]
        vuln_ids = []
        for i, vd in enumerate(vulns_data):
            vuln = Vulnerability(target_id=body.target_id, asset_id=asset_ids[i % len(asset_ids)], **vd)
            session.add(vuln)
            await session.flush()
            vuln_ids.append(vuln.id)

        # --- Cloud Assets ---
        session.add(CloudAsset(
            target_id=body.target_id, provider="AWS", asset_type="s3_bucket",
            url="https://test-bucket.s3.amazonaws.com", is_public=True,
            findings={"listing": True},
        ))
        session.add(CloudAsset(
            target_id=body.target_id, provider="Azure", asset_type="blob_container",
            url="https://test.blob.core.windows.net/data", is_public=False,
        ))

        # --- Alert ---
        session.add(Alert(
            target_id=body.target_id, vulnerability_id=vuln_ids[0],
            alert_type="critical_vuln",
            message="Critical: SQL Injection in login", is_read=False,
        ))

        # --- Jobs (simulated worker states) ---
        now = datetime.now(timezone.utc)
        jobs_data = [
            {"container_name": f"webbh-recon-t{body.target_id}",
             "current_phase": "passive_discovery", "status": "RUNNING",
             "last_tool_executed": "subfinder", "last_seen": now},
            {"container_name": f"webbh-recon-t{body.target_id}-2",
             "current_phase": "active_probing", "status": "COMPLETED",
             "last_tool_executed": "httpx", "last_seen": now},
        ]
        job_ids = []
        for jd in jobs_data:
            job = JobState(target_id=body.target_id, **jd)
            session.add(job)
            await session.flush()
            job_ids.append(job.id)

        await session.commit()

    return {
        "seeded": True,
        "target_id": body.target_id,
        "assets": len(assets_data),
        "vulnerabilities": len(vulns_data),
        "cloud_assets": 2,
        "alerts": 1,
        "asset_ids": asset_ids,
        "vuln_ids": vuln_ids,
        "job_ids": job_ids,
    }


@app.post("/api/v1/test/emit-event")
async def test_emit_event(body: TestEmitEventRequest):
    """Push an SSE event to a target's event stream for e2e testing.

    Guarded by ENABLE_TEST_SEED=true -- returns 404 in production.
    """
    if not ENABLE_TEST_SEED:
        raise HTTPException(status_code=404, detail="Not found")

    await push_task(f"events:{body.target_id}", body.event_data)
    return {"emitted": True}
