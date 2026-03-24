"""Docker SDK wrapper for managing worker containers.

Provides start / stop / restart / status / resource-guard operations used by
the event engine and the ``/api/v1/control`` endpoint.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import docker
import psutil
from docker.errors import NotFound, ImageNotFound, APIError
from lib_webbh import setup_logger

logger = setup_logger("worker_manager")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NETWORK_NAME = os.environ.get("DOCKER_NETWORK", "webbh-net")
CPU_THRESHOLD = float(os.environ.get("CPU_THRESHOLD", "85.0"))     # percent
MEM_THRESHOLD = float(os.environ.get("MEM_THRESHOLD", "85.0"))     # percent


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ContainerInfo:
    name: str
    status: str          # running | exited | paused | ...
    image: str
    started_at: Optional[str] = None


@dataclass
class ResourceSnapshot:
    cpu_percent: float
    memory_percent: float
    is_healthy: bool     # True if below thresholds


# ---------------------------------------------------------------------------
# Client singleton
# ---------------------------------------------------------------------------
_client: docker.DockerClient | None = None


def get_client() -> docker.DockerClient:
    """Return a Docker client connected via the mounted socket."""
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


# ---------------------------------------------------------------------------
# Container lifecycle
# ---------------------------------------------------------------------------
async def start_worker(
    image: str,
    container_name: str,
    environment: dict | None = None,
    volumes: dict | None = None,
) -> str | None:
    """Start a worker container. Returns container ID or None on failure.

    Runs the blocking Docker SDK call in a thread-pool executor so we don't
    block the async event loop.
    """
    loop = asyncio.get_running_loop()

    def _run() -> str | None:
        client = get_client()

        # If a container with this name already exists, remove it first
        try:
            old = client.containers.get(container_name)
            if old.status == "running":
                logger.info("Container already running", extra={"container": container_name})
                return old.id
            old.remove(force=True)
        except NotFound:
            pass

        try:
            container = client.containers.run(
                image=image,
                name=container_name,
                detach=True,
                environment=environment or {},
                volumes=volumes or {},
                network=NETWORK_NAME,
                restart_policy={"Name": "on-failure", "MaximumRetryCount": 3},
            )
            logger.info(
                "Worker started",
                extra={"container": container_name, "image": image, "id": container.id},
            )
            return container.id
        except ImageNotFound:
            logger.warning(
                "Image not found — worker skipped",
                extra={"image": image, "container": container_name},
            )
            return None
        except APIError as exc:
            logger.error(
                "Docker API error starting worker",
                extra={"container": container_name, "error": str(exc)},
            )
            return None

    return await loop.run_in_executor(None, _run)


async def stop_worker(container_name: str, timeout: int = 10) -> bool:
    """Gracefully stop a running container."""
    loop = asyncio.get_running_loop()

    def _run() -> bool:
        try:
            container = get_client().containers.get(container_name)
            container.reload()
            if container.status == "exited":
                logger.info("Worker already stopped", extra={"container": container_name})
                return True
            container.stop(timeout=timeout)
            logger.info("Worker stopped", extra={"container": container_name})
            return True
        except NotFound:
            logger.warning("Container not found for stop", extra={"container": container_name})
            return False
        except APIError as exc:
            logger.error("Error stopping worker", extra={"container": container_name, "error": str(exc)})
            return False

    return await loop.run_in_executor(None, _run)


async def restart_worker(container_name: str, timeout: int = 10) -> bool:
    """Restart a container."""
    loop = asyncio.get_running_loop()

    def _run() -> bool:
        try:
            container = get_client().containers.get(container_name)
            container.restart(timeout=timeout)
            logger.info("Worker restarted", extra={"container": container_name})
            return True
        except NotFound:
            logger.warning("Container not found for restart", extra={"container": container_name})
            return False
        except APIError as exc:
            logger.error("Error restarting worker", extra={"container": container_name, "error": str(exc)})
            return False

    return await loop.run_in_executor(None, _run)


async def pause_worker(container_name: str) -> bool:
    """Pause a running container."""
    loop = asyncio.get_running_loop()

    def _run() -> bool:
        try:
            container = get_client().containers.get(container_name)
            container.reload()
            if container.status == "paused":
                logger.info("Worker already paused", extra={"container": container_name})
                return True
            container.pause()
            logger.info("Worker paused", extra={"container": container_name})
            return True
        except NotFound:
            logger.warning("Container not found for pause", extra={"container": container_name})
            return False
        except APIError as exc:
            logger.error("Error pausing worker", extra={"container": container_name, "error": str(exc)})
            return False

    return await loop.run_in_executor(None, _run)


async def unpause_worker(container_name: str) -> bool:
    """Unpause a paused container."""
    loop = asyncio.get_running_loop()

    def _run() -> bool:
        try:
            container = get_client().containers.get(container_name)
            container.reload()
            if container.status == "running":
                logger.info("Worker already running", extra={"container": container_name})
                return True
            container.unpause()
            logger.info("Worker unpaused", extra={"container": container_name})
            return True
        except NotFound:
            return False
        except APIError:
            return False

    return await loop.run_in_executor(None, _run)


async def kill_worker(container_name: str) -> bool:
    """Force-kill a container (for zombie cleanup)."""
    loop = asyncio.get_running_loop()

    def _run() -> bool:
        try:
            container = get_client().containers.get(container_name)
            container.kill()
            container.remove(force=True)
            logger.info("Worker killed (zombie cleanup)", extra={"container": container_name})
            return True
        except NotFound:
            return False
        except APIError as exc:
            logger.error("Error killing worker", extra={"container": container_name, "error": str(exc)})
            return False

    return await loop.run_in_executor(None, _run)


# ---------------------------------------------------------------------------
# Status & inspection
# ---------------------------------------------------------------------------
async def get_container_status(container_name: str) -> ContainerInfo | None:
    """Return status info for a container, or None if not found."""
    loop = asyncio.get_running_loop()

    def _run() -> ContainerInfo | None:
        try:
            c = get_client().containers.get(container_name)
            return ContainerInfo(
                name=c.name,
                status=c.status,
                image=str(c.image.tags[0]) if c.image.tags else str(c.image.id[:12]),
                started_at=c.attrs.get("State", {}).get("StartedAt"),
            )
        except NotFound:
            return None

    return await loop.run_in_executor(None, _run)


async def list_webbh_containers() -> list[ContainerInfo]:
    """List all containers on the webbh-net network."""
    loop = asyncio.get_running_loop()

    def _run() -> list[ContainerInfo]:
        client = get_client()
        result: list[ContainerInfo] = []
        for c in client.containers.list(all=True):
            nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
            if NETWORK_NAME in nets:
                result.append(ContainerInfo(
                    name=c.name,
                    status=c.status,
                    image=str(c.image.tags[0]) if c.image.tags else str(c.image.id[:12]),
                    started_at=c.attrs.get("State", {}).get("StartedAt"),
                ))
        return result

    return await loop.run_in_executor(None, _run)


# ---------------------------------------------------------------------------
# Resource guard
# ---------------------------------------------------------------------------
async def check_resources() -> ResourceSnapshot:
    """Check host CPU and memory usage against thresholds."""
    loop = asyncio.get_running_loop()

    def _run() -> ResourceSnapshot:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        return ResourceSnapshot(
            cpu_percent=cpu,
            memory_percent=mem,
            is_healthy=cpu < CPU_THRESHOLD and mem < MEM_THRESHOLD,
        )

    return await loop.run_in_executor(None, _run)


async def should_queue() -> bool:
    """Return True if system resources are too high to start new workers."""
    snapshot = await check_resources()
    if not snapshot.is_healthy:
        logger.warning(
            "Resource guard: system under pressure",
            extra={"cpu": snapshot.cpu_percent, "memory": snapshot.memory_percent},
        )
    return not snapshot.is_healthy
