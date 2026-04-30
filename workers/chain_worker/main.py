# workers/chain_worker/main.py
from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import datetime
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, Target
from lib_webbh.logger import redact_sensitive
from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.scope import ScopeManager
from sqlalchemy import select

from workers.chain_worker.pipeline import Pipeline

# Import chains package so templates register via decorator
import workers.chain_worker.chains  # noqa: F401

logger = setup_logger("chain_worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "chain-worker-unknown")


async def _start_zap() -> subprocess.Popen | None:
    try:
        proc = subprocess.Popen(
            ["zap.sh", "-daemon", "-port", str(ZAP_PORT), "-config", "api.disablekey=true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info("ZAP daemon started", extra={"port": ZAP_PORT, "pid": proc.pid})
        return proc
    except FileNotFoundError:
        logger.warning("ZAP not found, skipping")
        return None
    except OSError as exc:
        logger.error("Failed to start ZAP", extra={"error": str(exc)})
        return None


async def _wait_for_zap(retries: int = 30, delay: float = 2.0) -> bool:
    import aiohttp
    for _ in range(retries):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{ZAP_PORT}/JSON/core/view/version/") as resp:
                    if resp.status == 200:
                        logger.info("ZAP ready")
                        return True
        except Exception:
            pass
        await asyncio.sleep(delay)
    logger.error("ZAP failed to start")
    return False


async def _start_msfrpcd() -> subprocess.Popen | None:
    try:
        proc = subprocess.Popen(
            ["msfrpcd", "-P", MSFRPC_PASS, "-p", str(MSFRPC_PORT), "-S", "-f"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info("msfrpcd started", extra={"port": MSFRPC_PORT, "pid": proc.pid})
        return proc
    except FileNotFoundError:
        logger.warning("msfrpcd not found, skipping")
        return None
    except OSError as exc:
        logger.error("Failed to start msfrpcd", extra={"error": str(exc)})
        return None


def _terminate_subprocess(proc: subprocess.Popen | None, name: str, timeout: float = 10.0) -> None:
    """Terminate a subprocess, escalating to SIGKILL if it does not exit in time."""
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("%s did not terminate within %.1fs; sending SIGKILL", name, timeout)
        proc.kill()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            logger.error("%s could not be killed", name)


async def _wait_for_msfrpcd(retries: int = 30, delay: float = 2.0) -> bool:
    for _ in range(retries):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            MsfRpcClient(MSFRPC_PASS, port=MSFRPC_PORT, ssl=True)
            logger.info("msfrpcd ready")
            return True
        except Exception:
            pass
        await asyncio.sleep(delay)
    logger.error("msfrpcd failed to start")
    return False


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    while True:
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                row = (await session.execute(stmt)).scalar_one_or_none()
                if row:
                    row.last_seen = datetime.utcnow()
                    await session.commit()
        except Exception:
            pass
        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def handle_message(msg_id: str, data: dict[str, Any]) -> None:
    target_id = data["target_id"]
    container_name = get_container_name()
    log = logger.bind(target_id=target_id, container=container_name)
    log.info("Received chain task", extra={"trigger": data.get("trigger_phase")})

    async with get_session() as session:
        try:
            target = (await session.execute(
                select(Target).where(Target.id == target_id)
            )).scalar_one_or_none()
            if target is None:
                log.error("Target not found")
                return
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            job = (await session.execute(stmt)).scalar_one_or_none()
            if job is None:
                job = JobState(
                    target_id=target_id, container_name=container_name,
                    status="RUNNING", current_phase="init",
                    last_seen=datetime.utcnow(),
                )
                session.add(job)
            else:
                job.status = "RUNNING"
                job.current_phase = "init"
                job.last_seen = datetime.utcnow()
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    scope_manager = ScopeManager(target.target_profile or {})
    heartbeat = asyncio.create_task(_heartbeat_loop(target_id, container_name))

    try:
        pipeline = Pipeline()
        await pipeline.run(
            target=target, scope_manager=scope_manager,
            target_id=target_id, container_name=container_name,
        )
    except Exception as exc:
        log.error("Pipeline failed", extra={"error": str(exc)})
        async with get_session() as session:
            try:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                job = (await session.execute(stmt)).scalar_one_or_none()
                if job:
                    job.status = "FAILED"
                    job.error = redact_sensitive(str(exc))
                    await session.commit()
            except Exception:
                await session.rollback()
                log.exception("Failed to record FAILED status in JobState")
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass


async def main() -> None:
    logger.info("Chain worker starting")
    zap_proc = await _start_zap()
    msf_proc = await _start_msfrpcd()
    try:
        if zap_proc:
            await _wait_for_zap()
        if msf_proc:
            await _wait_for_msfrpcd()

        consumer_group = "chain_worker_group"
        consumer_name = get_container_name()
        logger.info("Listening for tasks", extra={"consumer": consumer_name})

        async for message in listen_priority_queues(
            "chain_worker_queue", consumer_group, consumer_name
        ):
            try:
                await handle_message(message["msg_id"], message["payload"])
            except Exception as e:
                logger.error("Message handling failed", extra={"error": str(e)})

            r = get_redis()
            await r.xack(message["stream"], consumer_group, message["msg_id"])
    finally:
        _terminate_subprocess(zap_proc, "ZAP")
        _terminate_subprocess(msf_proc, "msfrpcd")


if __name__ == "__main__":
    asyncio.run(main())
