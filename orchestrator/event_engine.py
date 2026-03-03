"""Event-driven worker engine and health-check system.

Monitors the database for new observations and triggers worker containers
via the Docker SDK.  Also runs a heartbeat loop for zombie cleanup and
auto-resume on startup.

Public coroutines (started by ``main.lifespan``):
    run_event_loop   – periodic DB poll + trigger evaluation
    run_heartbeat    – 60-second health / zombie / auto-resume cycle
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import func, select, update

from lib_webbh import (
    Alert,
    Asset,
    CloudAsset,
    JobState,
    Location,
    Parameter,
    Target,
    get_session,
    push_task,
    setup_logger,
)

from orchestrator import worker_manager

logger = setup_logger("event_engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
POLL_INTERVAL = int(os.environ.get("EVENT_POLL_INTERVAL", "15"))       # seconds
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "60"))   # seconds
ZOMBIE_TIMEOUT = int(os.environ.get("ZOMBIE_TIMEOUT", "600"))         # 10 minutes
PARAM_THRESHOLD = int(os.environ.get("PARAM_THRESHOLD", "20"))         # unique keys

# Worker image names (Phase 4+ will supply the real images)
WORKER_IMAGES = {
    "cloud_testing":   os.environ.get("WORKER_IMAGE_CLOUD",   "webbh/cloud-worker:latest"),
    "fuzzing":         os.environ.get("WORKER_IMAGE_FUZZING",  "webbh/fuzzing-worker:latest"),
    "webapp_testing":  os.environ.get("WORKER_IMAGE_WEBAPP",   "webbh/webapp-worker:latest"),
    "api_testing":     os.environ.get("WORKER_IMAGE_API",      "webbh/api-worker:latest"),
}

# Statuses that indicate a job is active and should not be re-triggered
ACTIVE_STATUSES = ["RUNNING", "QUEUED", "PAUSED", "STOPPED"]

# Shared volume mount passed to every worker
SHARED_VOLUME = {
    os.environ.get("SHARED_VOLUME_HOST", "./shared"): {
        "bind": "/app/shared",
        "mode": "rw",
    }
}


# ---------------------------------------------------------------------------
# SSE helper — push events to the per-target Redis stream
# ---------------------------------------------------------------------------
async def _emit_event(target_id: int, event: str, data: dict) -> None:
    """Push an SSE-consumable event to ``events:{target_id}``."""
    payload = {"event": event, "target_id": target_id, **data}
    await push_task(f"events:{target_id}", payload)


# ---------------------------------------------------------------------------
# Trigger helpers
# ---------------------------------------------------------------------------
async def _ensure_job(
    target_id: int,
    container_name: str,
    phase: str,
) -> None:
    """Create or update a job_state row for a triggered worker."""
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if job is None:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                current_phase=phase,
                status="RUNNING",
                last_seen=now,
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.current_phase = phase
            job.last_seen = now
        await session.commit()


def _worker_env(target_id: int) -> dict:
    """Environment variables passed to every worker container."""
    return {
        "TARGET_ID": str(target_id),
        "DB_HOST": os.environ.get("DB_HOST", "postgres"),
        "DB_PORT": os.environ.get("DB_PORT", "5432"),
        "DB_NAME": os.environ.get("DB_NAME", "webbh"),
        "DB_USER": os.environ.get("DB_USER", "webbh_admin"),
        "DB_PASS": os.environ.get("DB_PASS", ""),
        "REDIS_HOST": os.environ.get("REDIS_HOST", "redis"),
        "REDIS_PORT": os.environ.get("REDIS_PORT", "6379"),
    }


async def _trigger_worker(
    target_id: int,
    worker_key: str,
    phase: str,
) -> None:
    """Start a worker if resources allow, otherwise queue it."""
    image = WORKER_IMAGES[worker_key]
    container_name = f"webbh-{worker_key}-t{target_id}"

    if await worker_manager.should_queue():
        logger.info(
            "Resources low — queuing worker",
            extra={"container": container_name, "phase": phase},
        )
        await _ensure_job(target_id, container_name, phase)
        async with get_session() as session:
            stmt = (
                update(JobState)
                .where(JobState.container_name == container_name)
                .values(status="QUEUED")
            )
            await session.execute(stmt)
            await session.commit()
        return

    cid = await worker_manager.start_worker(
        image=image,
        container_name=container_name,
        environment=_worker_env(target_id),
        volumes=SHARED_VOLUME,
    )

    if cid:
        await _ensure_job(target_id, container_name, phase)
        await _emit_event(target_id, "WORKER_SPAWNED", {
            "container": container_name,
            "image": image,
            "phase": phase,
        })
    else:
        logger.warning(
            "Worker could not start (image missing?)",
            extra={"container": container_name, "image": image},
        )


# ---------------------------------------------------------------------------
# Trigger evaluation — called each poll cycle
# ---------------------------------------------------------------------------
async def _check_cloud_trigger() -> None:
    """If new cloud_assets appeared since the last completed cloud job, trigger cloud worker."""
    async with get_session() as session:
        # Subquery: targets with an active cloud job (skip them)
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-cloud_testing-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        # Subquery: latest completed cloud job's last_seen per target
        done_sub = (
            select(
                JobState.target_id,
                func.max(JobState.last_seen).label("done_at"),
            )
            .where(
                JobState.container_name.like("webbh-cloud_testing-%"),
                JobState.status.in_(["COMPLETED", "STOPPED", "FAILED"]),
            )
            .group_by(JobState.target_id)
        ).subquery()

        # Find targets with cloud_assets newer than the last completed job
        stmt = (
            select(CloudAsset.target_id)
            .outerjoin(done_sub, done_sub.c.target_id == CloudAsset.target_id)
            .where(
                CloudAsset.target_id.notin_(select(active_sub.c.target_id)),
            )
            .group_by(CloudAsset.target_id)
            .having(
                func.max(CloudAsset.created_at) > func.coalesce(
                    func.max(done_sub.c.done_at),
                    datetime(1970, 1, 1, tzinfo=timezone.utc),
                )
            )
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Cloud trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "cloud_testing", "cloud_enum")


async def _check_web_trigger() -> None:
    """If a location has port 80/443 open, trigger fuzzing + webapp workers."""
    async with get_session() as session:
        subq_fuzz = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-fuzzing-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        stmt = (
            select(Location.asset_id, Asset.target_id)
            .join(Asset, Location.asset_id == Asset.id)
            .where(
                Location.port.in_([80, 443]),
                Location.state == "open",
                Asset.target_id.notin_(select(subq_fuzz.c.target_id)),
            )
            .group_by(Location.asset_id, Asset.target_id)
        )
        result = await session.execute(stmt)
        rows = result.all()

    triggered: set[int] = set()
    for _, target_id in rows:
        if target_id not in triggered:
            triggered.add(target_id)
            logger.info("Web trigger fired", extra={"target_id": target_id})
            await _trigger_worker(target_id, "fuzzing", "fuzzing")
            await _trigger_worker(target_id, "webapp_testing", "webapp_testing")


async def _check_api_trigger() -> None:
    """If a target's parameters exceed the threshold, trigger API testing."""
    async with get_session() as session:
        stmt = (
            select(Asset.target_id, func.count(Parameter.id).label("param_count"))
            .join(Parameter, Parameter.asset_id == Asset.id)
            .group_by(Asset.target_id)
            .having(func.count(Parameter.id) > PARAM_THRESHOLD)
        )
        result = await session.execute(stmt)
        candidates = {row[0] for row in result.all()}

        # Exclude targets that already have a running/queued API job
        if candidates:
            stmt2 = (
                select(JobState.target_id)
                .where(
                    JobState.container_name.like("webbh-api_testing-%"),
                    JobState.status.in_(ACTIVE_STATUSES),
                    JobState.target_id.in_(candidates),
                )
            )
            result2 = await session.execute(stmt2)
            already_running = {row[0] for row in result2.all()}
            candidates -= already_running

    for tid in candidates:
        logger.info("API trigger fired", extra={"target_id": tid, "threshold": PARAM_THRESHOLD})
        await _trigger_worker(tid, "api_testing", "api_testing")


# ---------------------------------------------------------------------------
# Main event loop
# ---------------------------------------------------------------------------
async def run_event_loop() -> None:
    """Poll the database periodically and evaluate triggers."""
    logger.info("Event engine started", extra={"poll_interval": POLL_INTERVAL})

    # Short initial delay to let DB come up
    await asyncio.sleep(3)

    while True:
        try:
            await _check_cloud_trigger()
            await _check_web_trigger()
            await _check_api_trigger()
        except Exception:
            logger.exception("Error in event loop cycle")

        await asyncio.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Heartbeat / Zombie cleanup / Auto-resume
# ---------------------------------------------------------------------------
async def run_heartbeat() -> None:
    """Periodic health check, zombie cleanup, and queued-job promotion."""
    logger.info("Heartbeat started", extra={"interval": HEARTBEAT_INTERVAL})

    # Auto-resume on startup
    await _auto_resume()

    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            await _heartbeat_cycle()
        except Exception:
            logger.exception("Error in heartbeat cycle")


async def _heartbeat_cycle() -> None:
    """Single heartbeat iteration."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=ZOMBIE_TIMEOUT)

    async with get_session() as session:
        # Find RUNNING jobs
        stmt = select(JobState).where(JobState.status == "RUNNING")
        result = await session.execute(stmt)
        running_jobs = result.scalars().all()

    for job in running_jobs:
        info = await worker_manager.get_container_status(job.container_name)

        if info is None or info.status != "running":
            # Container gone or stopped — check if zombie
            if job.last_seen and job.last_seen < cutoff:
                logger.warning(
                    "ZOMBIE_RESTART — killing unresponsive job",
                    extra={"container": job.container_name, "last_seen": str(job.last_seen)},
                )
                await worker_manager.kill_worker(job.container_name)

                async with get_session() as session:
                    stmt = (
                        update(JobState)
                        .where(JobState.id == job.id)
                        .values(status="FAILED", last_seen=now)
                    )
                    await session.execute(stmt)
                    await session.commit()

                # Create alert
                async with get_session() as session:
                    alert = Alert(
                        target_id=job.target_id,
                        alert_type="ZOMBIE_RESTART",
                        message=f"Container {job.container_name} was unresponsive for >{ZOMBIE_TIMEOUT}s and was killed.",
                    )
                    session.add(alert)
                    await session.commit()
            else:
                # Container gone but within timeout — mark FAILED
                async with get_session() as session:
                    stmt = (
                        update(JobState)
                        .where(JobState.id == job.id)
                        .values(status="FAILED", last_seen=now)
                    )
                    await session.execute(stmt)
                    await session.commit()
        else:
            # Container running — update last_seen
            async with get_session() as session:
                stmt = (
                    update(JobState)
                    .where(JobState.id == job.id)
                    .values(last_seen=now)
                )
                await session.execute(stmt)
                await session.commit()

    # Promote QUEUED jobs if resources are available
    if not await worker_manager.should_queue():
        async with get_session() as session:
            stmt = select(JobState).where(JobState.status == "QUEUED").order_by(JobState.created_at)
            result = await session.execute(stmt)
            queued = result.scalars().all()

        for job in queued:
            # Derive worker key from container name (e.g. webbh-fuzzing-t1 -> fuzzing)
            parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
            worker_key = parts[0] if parts else None
            if worker_key and worker_key in WORKER_IMAGES:
                await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)
                # Re-check resources after each start
                if await worker_manager.should_queue():
                    break


async def _auto_resume() -> None:
    """On startup, find RUNNING jobs with no active container and restart."""
    logger.info("Auto-resume: checking for orphaned jobs")

    async with get_session() as session:
        stmt = select(JobState).where(JobState.status == "RUNNING")
        result = await session.execute(stmt)
        running_jobs = result.scalars().all()

    resumed = 0
    for job in running_jobs:
        info = await worker_manager.get_container_status(job.container_name)
        if info is None or info.status != "running":
            logger.info(
                "Auto-resume: restarting orphaned job",
                extra={
                    "container": job.container_name,
                    "last_tool": job.last_tool_executed,
                },
            )
            parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
            worker_key = parts[0] if parts else None
            if worker_key and worker_key in WORKER_IMAGES:
                await _trigger_worker(
                    job.target_id,
                    worker_key,
                    job.current_phase or worker_key,
                )
                resumed += 1

    logger.info("Auto-resume complete", extra={"resumed": resumed})
