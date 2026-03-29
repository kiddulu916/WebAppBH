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
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

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
from lib_webbh.database import MobileApp, Vulnerability

from orchestrator import worker_manager

logger = setup_logger("event_engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
POLL_INTERVAL = int(os.environ.get("EVENT_POLL_INTERVAL", "15"))       # seconds
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "60"))   # seconds
ZOMBIE_TIMEOUT = int(os.environ.get("ZOMBIE_TIMEOUT", "600"))         # 10 minutes
PARAM_THRESHOLD = int(os.environ.get("PARAM_THRESHOLD", "20"))         # unique keys
ZOMBIE_MAX_RETRIES = int(os.environ.get("ZOMBIE_MAX_RETRIES", "3"))

# Worker image names
WORKER_IMAGES = {
    "recon":           os.environ.get("WORKER_IMAGE_RECON",      "webbh/recon-core:latest"),
    "cloud_testing":   os.environ.get("WORKER_IMAGE_CLOUD",      "webbh/cloud-worker:latest"),
    "fuzzing":         os.environ.get("WORKER_IMAGE_FUZZING",    "webbh/fuzzing-worker:latest"),
    "webapp_testing":  os.environ.get("WORKER_IMAGE_WEBAPP",     "webbh/webapp-worker:latest"),
    "api_testing":     os.environ.get("WORKER_IMAGE_API",        "webbh/api-worker:latest"),
    "network":         os.environ.get("WORKER_IMAGE_NETWORK",    "webbh/network-worker:latest"),
    "mobile":          os.environ.get("WORKER_IMAGE_MOBILE",     "webbh/mobile-worker:latest"),
    "chain":           os.environ.get("WORKER_IMAGE_CHAIN",      "webbh/chain-worker:latest"),
    "vulnscan":        os.environ.get("WORKER_IMAGE_VULNSCAN",   "webbh/vuln-scanner:latest"),
    "reporting":       os.environ.get("WORKER_IMAGE_REPORTING",  "webbh/reporting-worker:latest"),
}

# Statuses that indicate a job is active and should not be re-triggered
ACTIVE_STATUSES = ["RUNNING", "QUEUED", "PAUSED", "STOPPED"]

# Worker keys whose completion should trigger the chain worker (phases 4-11)
CHAIN_TRIGGER_WORKERS = {"recon", "cloud_testing", "fuzzing", "webapp_testing", "api_testing"}

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

        now = datetime.utcnow()
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
        "WEB_APP_BH_API_KEY": os.environ.get("WEB_APP_BH_API_KEY", ""),
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
                    datetime(1970, 1, 1),
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


async def _check_recon_trigger() -> None:
    """Trigger recon worker for new targets with no active/completed recon job."""
    async with get_session() as session:
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-recon-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        completed_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-recon-%"),
                JobState.status.in_(["COMPLETED", "KILLED"]),
            )
        ).subquery()

        stmt = (
            select(Target.id)
            .where(
                Target.id.notin_(select(active_sub.c.target_id)),
                Target.id.notin_(select(completed_sub.c.target_id)),
            )
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Recon trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "recon", "passive_discovery")


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


async def _trigger_chain_worker(target_id: int, completed_phase: str) -> None:
    """Push a task to chain_queue so the chain worker evaluates new findings."""
    await push_task("chain_queue", {
        "target_id": target_id,
        "trigger_phase": completed_phase,
        "run_id": uuid4().hex,
    })
    logger.info(
        "Chain trigger fired",
        extra={"target_id": target_id, "trigger_phase": completed_phase},
    )


async def _check_chain_trigger() -> None:
    """Trigger chain worker when a phase 4-11 worker completes."""
    async with get_session() as session:
        # Find COMPLETED jobs from chain-trigger workers that haven't been followed
        # by a chain run yet (no active chain job for that target).
        active_chain_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-chain_%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        # Latest chain job completion per target
        chain_done_sub = (
            select(
                JobState.target_id,
                func.max(JobState.last_seen).label("done_at"),
            )
            .where(
                JobState.container_name.like("webbh-chain_%"),
                JobState.status.in_(["COMPLETED", "FAILED"]),
            )
            .group_by(JobState.target_id)
        ).subquery()

        # Find worker completions newer than the last chain run
        stmt = (
            select(
                JobState.target_id,
                JobState.container_name,
            )
            .outerjoin(chain_done_sub, chain_done_sub.c.target_id == JobState.target_id)
            .where(
                JobState.status == "COMPLETED",
                JobState.target_id.notin_(select(active_chain_sub.c.target_id)),
                JobState.last_seen > func.coalesce(
                    chain_done_sub.c.done_at,
                    datetime(1970, 1, 1),
                ),
            )
            .group_by(JobState.target_id, JobState.container_name)
        )
        result = await session.execute(stmt)
        rows = result.all()

    triggered: set[int] = set()
    for target_id, container_name in rows:
        worker_key = container_name.replace("webbh-", "").rsplit("-t", 1)[0]
        if worker_key in CHAIN_TRIGGER_WORKERS and target_id not in triggered:
            triggered.add(target_id)
            await _trigger_chain_worker(target_id, worker_key)


async def _check_network_trigger() -> None:
    """Trigger network worker when non-web ports are open (not 80/443)."""
    async with get_session() as session:
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-network-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        completed_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-network-%"),
                JobState.status.in_(["COMPLETED", "KILLED"]),
            )
        ).subquery()

        stmt = (
            select(Asset.target_id)
            .join(Location, Location.asset_id == Asset.id)
            .where(
                Location.state == "open",
                Location.port.notin_([80, 443]),
                Asset.target_id.notin_(select(active_sub.c.target_id)),
                Asset.target_id.notin_(select(completed_sub.c.target_id)),
            )
            .group_by(Asset.target_id)
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Network trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "network", "port_discovery")


async def _check_vulnscan_trigger() -> None:
    """Trigger vuln scanner when fuzzing/webapp/api workers complete."""
    async with get_session() as session:
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-vulnscan-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        vulnscan_done_sub = (
            select(
                JobState.target_id,
                func.max(JobState.last_seen).label("done_at"),
            )
            .where(
                JobState.container_name.like("webbh-vulnscan-%"),
                JobState.status.in_(["COMPLETED", "FAILED"]),
            )
            .group_by(JobState.target_id)
        ).subquery()

        # Find targets where fuzzing/webapp/api completed after last vulnscan
        prereq_workers = ["webbh-fuzzing-%", "webbh-webapp_testing-%", "webbh-api_testing-%"]
        conditions = [JobState.container_name.like(pat) for pat in prereq_workers]

        from sqlalchemy import or_

        stmt = (
            select(JobState.target_id)
            .outerjoin(vulnscan_done_sub, vulnscan_done_sub.c.target_id == JobState.target_id)
            .where(
                or_(*conditions),
                JobState.status == "COMPLETED",
                JobState.target_id.notin_(select(active_sub.c.target_id)),
                JobState.last_seen > func.coalesce(
                    vulnscan_done_sub.c.done_at,
                    datetime(1970, 1, 1),
                ),
            )
            .group_by(JobState.target_id)
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Vulnscan trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "vulnscan", "nuclei_sweep")


async def _check_mobile_trigger() -> None:
    """Trigger mobile worker when MobileApp records exist with no active mobile job."""
    async with get_session() as session:
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-mobile-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        completed_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-mobile-%"),
                JobState.status.in_(["COMPLETED", "KILLED"]),
            )
        ).subquery()

        stmt = (
            select(MobileApp.target_id)
            .where(
                MobileApp.target_id.notin_(select(active_sub.c.target_id)),
                MobileApp.target_id.notin_(select(completed_sub.c.target_id)),
            )
            .group_by(MobileApp.target_id)
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Mobile trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "mobile", "acquire_decompile")


async def _check_reporting_trigger() -> None:
    """Trigger reporting worker when chain worker completes for a target."""
    async with get_session() as session:
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-reporting-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        reporting_done_sub = (
            select(
                JobState.target_id,
                func.max(JobState.last_seen).label("done_at"),
            )
            .where(
                JobState.container_name.like("webbh-reporting-%"),
                JobState.status.in_(["COMPLETED", "FAILED"]),
            )
            .group_by(JobState.target_id)
        ).subquery()

        # Trigger when chain worker completed after last report
        stmt = (
            select(JobState.target_id)
            .outerjoin(reporting_done_sub, reporting_done_sub.c.target_id == JobState.target_id)
            .where(
                JobState.container_name.like("webbh-chain-%"),
                JobState.status == "COMPLETED",
                JobState.target_id.notin_(select(active_sub.c.target_id)),
                JobState.last_seen > func.coalesce(
                    reporting_done_sub.c.done_at,
                    datetime(1970, 1, 1),
                ),
            )
            .group_by(JobState.target_id)
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Reporting trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "reporting", "data_gathering")


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
            await _check_recon_trigger()
            await _check_cloud_trigger()
            await _check_web_trigger()
            await _check_api_trigger()
            await _check_network_trigger()
            await _check_mobile_trigger()
            await _check_vulnscan_trigger()
            await _check_chain_trigger()
            await _check_reporting_trigger()
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
    """Single heartbeat iteration — batched DB access."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=ZOMBIE_TIMEOUT)

    # --- Read phase ---
    async with get_session() as session:
        stmt = select(JobState).where(JobState.status == "RUNNING")
        result = await session.execute(stmt)
        running_jobs = result.scalars().all()

    if not running_jobs:
        await _promote_queued_jobs()
        await _check_scheduled_scans()
        return

    # Gather container statuses concurrently
    statuses = await asyncio.gather(
        *(worker_manager.get_container_status(j.container_name) for j in running_jobs)
    )

    # Classify jobs
    healthy_ids: list[int] = []
    grace_jobs: list[JobState] = []
    zombie_jobs: list[JobState] = []

    for job, info in zip(running_jobs, statuses):
        if info is not None and info.status == "running":
            healthy_ids.append(job.id)
        else:
            last_seen = job.last_seen
            if last_seen and last_seen < cutoff:
                zombie_jobs.append(job)
            else:
                grace_jobs.append(job)

    # --- Write phase ---
    # Bulk update last_seen for healthy jobs
    if healthy_ids:
        async with get_session() as session:
            stmt = (
                update(JobState)
                .where(JobState.id.in_(healthy_ids))
                .values(last_seen=now)
            )
            await session.execute(stmt)
            await session.commit()

    # Log grace-period jobs
    for job in grace_jobs:
        logger.info(
            "Container missing but within grace period",
            extra={"container": job.container_name, "last_seen": str(job.last_seen)},
        )

    # Handle zombies
    for job in zombie_jobs:
        await _handle_zombie(job, now)

    # Promote queued jobs
    await _promote_queued_jobs()

    # Check scheduled scans
    await _check_scheduled_scans()


async def _handle_zombie(job: JobState, now: datetime) -> None:
    """Kill a zombie job, create alert, and restart with exponential backoff."""
    logger.warning(
        "ZOMBIE_RESTART — killing unresponsive job",
        extra={"container": job.container_name, "last_seen": str(job.last_seen)},
    )
    await worker_manager.kill_worker(job.container_name)

    async with get_session() as session:
        # Mark FAILED
        stmt = update(JobState).where(JobState.id == job.id).values(status="FAILED", last_seen=now)
        await session.execute(stmt)

        # Count prior zombie restarts
        retry_stmt = (
            select(func.count(Alert.id))
            .where(
                Alert.target_id == job.target_id,
                Alert.alert_type == "ZOMBIE_RESTART",
                Alert.message.like(f"%{job.container_name}%"),
            )
        )
        result = await session.execute(retry_stmt)
        retry_count = result.scalar() or 0

        if retry_count >= ZOMBIE_MAX_RETRIES:
            alert = Alert(
                target_id=job.target_id,
                alert_type="CRITICAL_ALERT",
                message=f"Container {job.container_name} exceeded {ZOMBIE_MAX_RETRIES} zombie restarts. Permanently failed.",
            )
            session.add(alert)
        else:
            backoff_seconds = 30 * (2 ** retry_count)
            alert = Alert(
                target_id=job.target_id,
                alert_type="ZOMBIE_RESTART",
                message=f"Container {job.container_name} unresponsive for >{ZOMBIE_TIMEOUT}s. Retry {retry_count + 1}/{ZOMBIE_MAX_RETRIES} after {backoff_seconds}s backoff.",
            )
            session.add(alert)
        await session.commit()

    if retry_count >= ZOMBIE_MAX_RETRIES:
        await _emit_event(job.target_id, "CRITICAL_ALERT", {
            "container": job.container_name,
            "message": f"Exceeded {ZOMBIE_MAX_RETRIES} zombie restarts",
        })
    else:
        backoff_seconds = 30 * (2 ** retry_count)
        loop = asyncio.get_running_loop()
        loop.call_later(
            backoff_seconds,
            lambda j=job: asyncio.create_task(_delayed_restart(j)),
        )


async def _delayed_restart(job: JobState) -> None:
    """Restart a worker after exponential backoff delay."""
    parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
    worker_key = parts[0] if parts else None
    if worker_key and worker_key in WORKER_IMAGES:
        logger.info("Delayed restart executing", extra={
            "container": job.container_name,
            "worker_key": worker_key,
        })
        await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)


async def _check_scheduled_scans() -> None:
    """Trigger rescans for scheduled scans whose next_run_at has passed."""
    from lib_webbh.database import ScheduledScan
    from lib_webbh.cron_utils import next_run

    now = datetime.utcnow()
    async with get_session() as session:
        stmt = select(ScheduledScan).where(
            ScheduledScan.enabled == True,
            ScheduledScan.next_run_at != None,
            ScheduledScan.next_run_at <= now,
        )
        result = await session.execute(stmt)
        due = result.scalars().all()

    for scan in due:
        logger.info("Scheduled scan triggered", extra={
            "target_id": scan.target_id, "cron": scan.cron_expression,
        })
        await push_task("recon_queue", {
            "target_id": scan.target_id,
            "rescan": True,
            "scheduled": True,
            "playbook": scan.playbook,
        })
        async with get_session() as session:
            stmt_update = (
                update(ScheduledScan)
                .where(ScheduledScan.id == scan.id)
                .values(last_run_at=now, next_run_at=next_run(scan.cron_expression, now))
            )
            await session.execute(stmt_update)
            await session.commit()


async def _promote_queued_jobs() -> None:
    """Promote QUEUED jobs if resources are available."""
    if await worker_manager.should_queue():
        return

    async with get_session() as session:
        stmt = select(JobState).where(JobState.status == "QUEUED").order_by(JobState.created_at)
        result = await session.execute(stmt)
        queued = result.scalars().all()

    for job in queued:
        parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
        worker_key = parts[0] if parts else None
        if worker_key and worker_key in WORKER_IMAGES:
            await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)
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


# ---------------------------------------------------------------------------
# Redis background listener — real-time reactive path
# ---------------------------------------------------------------------------
async def _dispatch_recon_event(msg_id: str, data: dict) -> None:
    """Fan out a recon_queue message to the appropriate work queue."""
    asset_type = data.get("asset_type")
    target_id = data.get("target_id")

    if asset_type == "location":
        port = data.get("port")
        state = data.get("state")
        if port in (80, 443) and state == "open":
            await push_task("fuzzing_queue", data)
            await push_task("webapp_queue", data)
            logger.info("Dispatched web location to fuzzing + webapp queues",
                        extra={"target_id": target_id, "asset_id": data.get("asset_id")})

    elif asset_type == "cloud_asset":
        await push_task("cloud_queue", data)
        logger.info("Dispatched cloud asset to cloud_queue",
                    extra={"target_id": target_id})

    elif asset_type == "param":
        await push_task("api_queue", data)
        logger.info("Dispatched param to api_queue",
                    extra={"target_id": target_id})


async def run_redis_listener() -> None:
    """Listen on recon_queue and fan out to work queues.

    Complements the DB poll loop — this provides sub-second reactivity.
    """
    from lib_webbh import listen_queue

    logger.info("Redis listener started on recon_queue")
    await listen_queue(
        queue="recon_queue",
        group="orchestrator",
        consumer="event-engine",
        callback=_dispatch_recon_event,
    )


# ---------------------------------------------------------------------------
# Auto-scaling — monitor queue depth and scale workers
# ---------------------------------------------------------------------------
AUTOSCALE_INTERVAL = int(os.environ.get("AUTOSCALE_INTERVAL", "30"))
QUEUE_PRESSURE_THRESHOLD = int(os.environ.get("QUEUE_PRESSURE_THRESHOLD", "50"))

QUEUE_TO_WORKER = {
    "recon_queue": "recon",
    "fuzzing_queue": "fuzzing",
    "webapp_queue": "webapp",
    "cloud_queue": "cloud",
    "api_queue": "api",
}


async def run_autoscaler() -> None:
    """Monitor queue depths and log scaling recommendations."""
    from lib_webbh.messaging import get_pending
    from lib_webbh.queue_monitor import assess_queue_health

    logger.info("Autoscaler started", extra={"interval": AUTOSCALE_INTERVAL})
    await asyncio.sleep(5)

    while True:
        try:
            for queue_name, worker_key in QUEUE_TO_WORKER.items():
                try:
                    info = await get_pending(queue_name, f"{worker_key}_group")
                    pending = info.get("pending", 0)
                except Exception:
                    pending = 0

                health = assess_queue_health(pending, QUEUE_PRESSURE_THRESHOLD)

                if health.should_scale_up:
                    logger.warning(
                        "Queue pressure detected — scale up recommended",
                        extra={"queue": queue_name, "pending": pending,
                               "health": health.value, "worker": worker_key},
                    )
                    await _emit_event(0, "AUTOSCALE_RECOMMENDATION", {
                        "queue": queue_name, "worker": worker_key,
                        "pending": pending, "action": "scale_up",
                    })
                elif health.should_scale_down:
                    logger.debug(
                        "Queue idle — scale down possible",
                        extra={"queue": queue_name, "worker": worker_key},
                    )
        except Exception:
            logger.exception("Error in autoscaler cycle")

        await asyncio.sleep(AUTOSCALE_INTERVAL)
