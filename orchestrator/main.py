"""WebAppBH Framework Orchestrator — FastAPI application.

Endpoints
---------
POST /api/v1/targets       – initialise a new scan target
GET  /api/v1/status        – real-time job states
POST /api/v1/control       – pause / stop / restart workers
GET  /api/v1/stream/{id}   – SSE event stream per target
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select

from lib_webbh import (
    Alert,
    Asset,
    Base,
    JobState,
    Target,
    get_engine,
    get_session,
    push_task,
    setup_logger,
)

from orchestrator import event_engine, worker_manager

logger = setup_logger("orchestrator")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("WEB_APP_BH_API_KEY", "")
SHARED_CONFIG = Path(os.environ.get("SHARED_CONFIG_DIR", "/app/shared/config"))
SHARED_RAW = Path(os.environ.get("SHARED_RAW_DIR", "/app/shared/raw"))

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


# ---------------------------------------------------------------------------
# Lifespan — start / stop background tasks
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Orchestrator starting")

    # Ensure tables exist (idempotent)
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Start background tasks
    engine_task = asyncio.create_task(event_engine.run_event_loop(), name="event-engine")
    heartbeat_task = asyncio.create_task(event_engine.run_heartbeat(), name="heartbeat")
    logger.info("Background tasks started")

    yield

    # Shutdown
    engine_task.cancel()
    heartbeat_task.cancel()
    for task in (engine_task, heartbeat_task):
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
    from lib_webbh.messaging import get_redis

    queue = f"events:{target_id}"
    group = "sse_consumers"
    consumer = f"sse-{id(request)}"

    redis = get_redis()
    try:
        await redis.xgroup_create(queue, group, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    async def _generate():
        last_id = ">"
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

    return EventSourceResponse(_generate())


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
