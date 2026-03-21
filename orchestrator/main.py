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
GET   /api/v1/status               – real-time job states
POST  /api/v1/control              – pause / stop / restart workers
GET   /api/v1/stream/{id}          – SSE event stream per target
POST  /api/v1/targets/{id}/reports – trigger report generation
GET   /api/v1/targets/{id}/reports – list generated reports
GET   /api/v1/targets/{id}/reports/{filename} – download a report
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select
from sqlalchemy.orm import attributes, selectinload

from lib_webbh import (
    Alert,
    Asset,
    Base,
    CloudAsset,
    JobState,
    Location,
    Target,
    Vulnerability,
    get_engine,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.messaging import get_redis

from orchestrator import event_engine, worker_manager

logger = setup_logger("orchestrator")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("WEB_APP_BH_API_KEY", "")
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
    company_name: str
    base_domain: str
    target_profile: Optional[dict] = Field(
        default=None,
        description="Scope rules, rate limits, custom headers",
    )


class ControlAction(BaseModel):
    container_name: str
    action: str = Field(description="pause | stop | restart")


class AlertUpdate(BaseModel):
    is_read: bool


class TargetProfileUpdate(BaseModel):
    custom_headers: Optional[dict] = None
    rate_limits: Optional[dict] = None


class ReportCreate(BaseModel):
    formats: list[str] = Field(description="Report formats to generate: hackerone_md, bugcrowd_md, executive_pdf, technical_pdf")
    platform: str = Field(default="hackerone", description="Target platform: hackerone or bugcrowd")


# ---------------------------------------------------------------------------
# Lifespan — start / stop background tasks
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Orchestrator starting")

    # Ensure tables exist (idempotent)
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    if not API_KEY:
        logger.warning("WEB_APP_BH_API_KEY is not set — all endpoints are unauthenticated")

    # Start background tasks
    engine_task = asyncio.create_task(event_engine.run_event_loop(), name="event-engine")
    heartbeat_task = asyncio.create_task(event_engine.run_heartbeat(), name="heartbeat")
    redis_task = asyncio.create_task(event_engine.run_redis_listener(), name="redis-listener")
    logger.info("Background tasks started")

    yield

    # Shutdown
    engine_task.cancel()
    heartbeat_task.cancel()
    redis_task.cancel()
    for task in (engine_task, heartbeat_task, redis_task):
        try:
            await task
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
# POST /api/v1/targets — initialise a new scan
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets", status_code=201)
async def create_target(body: TargetCreate):
    async with get_session() as session:
        target = Target(
            company_name=body.company_name,
            base_domain=body.base_domain,
            target_profile=body.target_profile,
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

    # Generate tool-specific configs from target profile
    _generate_tool_configs(target.id, body.target_profile or {})

    logger.info(
        "Target initialised",
        extra={"target_id": target.id, "domain": body.base_domain},
    )

    return {
        "target_id": target.id,
        "company_name": target.company_name,
        "base_domain": target.base_domain,
        "profile_path": str(profile_path),
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
# GET /api/v1/stream/{target_id} — SSE
# ---------------------------------------------------------------------------
@app.get("/api/v1/stream/{target_id}")
async def stream_events(target_id: int, request: Request):
    """Server-Sent Events stream for a specific target.

    Publishes events: TOOL_PROGRESS, NEW_ASSET, CRITICAL_ALERT, WORKER_SPAWNED.
    Events are pushed to the ``events:{target_id}`` Redis stream by the event
    engine and consumed here.
    """
    queue = f"events:{target_id}"
    group = "sse_consumers"
    consumer = f"sse-{uuid4().hex}"

    redis = get_redis()
    try:
        await redis.xgroup_create(queue, group, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    async def _generate():
        last_id = ">"
        try:
            while True:
                if await request.is_disconnected():
                    break
                messages = await redis.xreadgroup(
                    groupname=group,
                    consumername=consumer,
                    streams={queue: last_id},
                    count=10,
                    block=2000,
                )
                for _, entries in messages:
                    for msg_id, data in entries:
                        payload = json.loads(data.get("payload", "{}"))
                        event_type = payload.get("event", "message")
                        yield {"event": event_type, "data": json.dumps(payload)}
                        await redis.xack(queue, group, msg_id)
        finally:
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
    async with get_session() as session:
        stmt = select(Target).order_by(Target.created_at.desc())
        result = await session.execute(stmt)
        targets = result.scalars().all()

    return {
        "targets": [
            {
                "id": t.id,
                "company_name": t.company_name,
                "base_domain": t.base_domain,
                "target_profile": t.target_profile,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
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

        vuln_count = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
        )).scalars().all()
        if not vuln_count:
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
    from fastapi.responses import FileResponse

    # Prevent path traversal
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = SHARED_REPORTS / str(target_id) / filename
    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = "application/pdf" if filepath.suffix == ".pdf" else "text/markdown"
    return FileResponse(
        path=str(filepath),
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


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
