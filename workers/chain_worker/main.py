# workers/chain_worker/main.py
from __future__ import annotations

import asyncio
import socket
import subprocess
from datetime import datetime, timezone

from sqlalchemy import delete, update

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, Target
from lib_webbh.logger import redact_sensitive
from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.scope import ScopeManager

from workers.chain_worker.pipeline import Pipeline

# Import chains package so templates register via decorator
import workers.chain_worker.chains  # noqa: F401

import os

logger = setup_logger("chain_worker")

WORKER_TYPE = "chain_worker"
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))


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
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning(f"{name} did not terminate within {timeout:.1f}s; sending SIGKILL")
        proc.kill()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            logger.error(f"{name} could not be killed")


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


async def main() -> None:
    logger.info("Chain worker starting")
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

    zap_proc = await _start_zap()
    msf_proc = await _start_msfrpcd()
    try:
        if zap_proc:
            await _wait_for_zap()
        if msf_proc:
            await _wait_for_msfrpcd()

        logger.info("Listening for tasks", extra={"consumer": consumer_name})

        async for message in listen_priority_queues(
            f"{WORKER_TYPE}_queue", consumer_group, consumer_name
        ):
            target_id = message["payload"]["target_id"]
            logger.info("Job received", extra={"target_id": target_id})

            try:
                async with get_session() as session:
                    await session.execute(
                        delete(JobState).where(
                            JobState.target_id == target_id,
                            JobState.container_name == WORKER_TYPE,
                        )
                    )
                    session.add(JobState(
                        target_id=target_id,
                        container_name=WORKER_TYPE,
                        status="RUNNING",
                        started_at=datetime.now(timezone.utc),
                    ))
                    await session.commit()

                async with get_session() as session:
                    target = await session.get(Target, target_id)
                if target is None:
                    logger.error("Target not found", extra={"target_id": target_id})
                    r = get_redis()
                    await r.xack(message["stream"], consumer_group, message["msg_id"])
                    continue

                scope_manager = ScopeManager(target.target_profile or {
                    "in_scope_domains": [f"*.{target.base_domain}", target.base_domain]
                })

                pipeline = Pipeline()
                await pipeline.run(
                    target=target,
                    scope_manager=scope_manager,
                    target_id=target_id,
                    container_name=WORKER_TYPE,
                )

                async with get_session() as session:
                    await session.execute(
                        update(JobState)
                        .where(JobState.target_id == target_id)
                        .where(JobState.container_name == WORKER_TYPE)
                        .values(status="COMPLETED", completed_at=datetime.now(timezone.utc))
                    )
                    await session.commit()

            except Exception as exc:
                logger.error("Job failed", extra={"target_id": target_id, "error": str(exc)})
                try:
                    async with get_session() as session:
                        await session.execute(
                            update(JobState)
                            .where(JobState.target_id == target_id)
                            .where(JobState.container_name == WORKER_TYPE)
                            .values(status="FAILED", error=redact_sensitive(str(exc))[:500])
                        )
                        await session.commit()
                except Exception:
                    pass

            r = get_redis()
            await r.xack(message["stream"], consumer_group, message["msg_id"])
    finally:
        _terminate_subprocess(zap_proc, "ZAP")
        _terminate_subprocess(msf_proc, "msfrpcd")


if __name__ == "__main__":
    asyncio.run(main())
