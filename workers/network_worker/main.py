# workers/network_worker/main.py
"""Network testing worker entry point.

Listens on ``network_queue`` and runs the 4-stage
network testing pipeline for each incoming target.
Manages msfrpcd lifecycle on startup.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_queue,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.network_worker.pipeline import Pipeline

logger = setup_logger("network-worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "network-worker-unknown")


async def _start_msfrpcd() -> asyncio.subprocess.Process | None:
    """Start msfrpcd as a background subprocess."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "msfrpcd",
            "-P", MSFRPC_PASS,
            "-p", str(MSFRPC_PORT),
            "-S",  # no SSL
            "-f",  # foreground (we manage lifecycle)
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"msfrpcd started on port {MSFRPC_PORT}")
        return proc
    except FileNotFoundError:
        logger.warning("msfrpcd not found — MSF checks will be unavailable")
        return None


async def _wait_for_msfrpcd(
    max_retries: int = 30, delay: float = 2.0,
) -> bool:
    """Wait for msfrpcd to accept connections."""
    for attempt in range(max_retries):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient

            MsfRpcClient(
                MSFRPC_PASS, server="127.0.0.1", port=MSFRPC_PORT, ssl=False,
            )
            logger.info("msfrpcd is ready")
            return True
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
    logger.error("msfrpcd failed to start within timeout")
    return False


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single network_queue message."""
    target_id = data.get("target_id")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info("Received network testing task", extra={"msg_id": msg_id})

    # Load target
    async with get_session() as session:
        stmt = select(Target).where(Target.id == target_id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

    if target is None:
        log.error(f"Target {target_id} not found in database")
        return

    container_name = get_container_name()
    profile = target.target_profile or {}
    scope_manager = ScopeManager(profile)

    # Ensure job_state row
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if job is None:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                current_phase="init",
                status="RUNNING",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.now(timezone.utc)
        await session.commit()

    # Run pipeline with heartbeat
    pipeline = Pipeline(target_id=target_id, container_name=container_name)
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(target_id, container_name)
    )

    try:
        await pipeline.run(target, scope_manager)
    except Exception:
        log.exception("Pipeline failed")
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "FAILED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    """Update job_state.last_seen every HEARTBEAT_INTERVAL seconds."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass


async def main() -> None:
    """Entry point: start msfrpcd, then listen on network_queue."""
    container_name = get_container_name()
    logger.info(
        "Network testing worker starting", extra={"container": container_name},
    )

    # Start msfrpcd daemon
    msf_proc = await _start_msfrpcd()
    if msf_proc:
        await _wait_for_msfrpcd()

    await listen_queue(
        queue="network_queue",
        group="network_group",
        consumer=container_name,
        callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
