"""E2E test infrastructure: stack lifecycle, HTTP client, SSE monitor, helpers."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx
import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
_BASE_URL = "http://localhost:8001"
_HEALTH_URL = f"{_BASE_URL}/api/v1/health"
LOG_IGNORE_PATTERNS = [
    "redis.exceptions.ConnectionError",
    "asyncpg.exceptions",
    "Connection refused",
    "Retrying",
]

# ---------------------------------------------------------------------------
# pytest hooks
# ---------------------------------------------------------------------------


def pytest_addoption(parser):
    parser.addoption(
        "--e2e",
        action="store_true",
        default=False,
        help="Run e2e tests requiring the live docker stack",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--e2e"):
        skip_e2e = pytest.mark.skip(reason="pass --e2e to run e2e tests")
        for item in items:
            if item.get_closest_marker("e2e"):
                item.add_marker(skip_e2e)


# ---------------------------------------------------------------------------
# Stack helpers
# ---------------------------------------------------------------------------


def _is_stack_running() -> bool:
    try:
        urllib.request.urlopen(_HEALTH_URL, timeout=2)
        return True
    except Exception:
        return False


def _wait_for_health(timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    delay = 1.0
    while time.monotonic() < deadline:
        if _is_stack_running():
            return
        time.sleep(delay)
        delay = min(delay * 2, 15)
    raise TimeoutError(f"Stack did not become healthy within {timeout}s")


def _read_api_key() -> str:
    key = os.environ.get("WEB_APP_BH_API_KEY")
    if key:
        return key
    env_file = _REPO_ROOT / "shared" / "config" / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("WEB_APP_BH_API_KEY="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError(
        "WEB_APP_BH_API_KEY not found in environment or shared/config/.env"
    )


# ---------------------------------------------------------------------------
# Stack fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def stack(request):
    if not request.config.getoption("--e2e"):
        yield
        return

    we_started_it = False
    if not _is_stack_running():
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                "docker-compose.yml",
                "-f",
                "docker-compose.test.yml",
                "up",
                "-d",
                "--build",
            ],
            cwd=_REPO_ROOT,
            check=True,
        )
        we_started_it = True
        _wait_for_health(120)

    yield

    if we_started_it:
        subprocess.run(
            ["docker", "compose", "down", "-v"],
            cwd=_REPO_ROOT,
            check=True,
        )


# ---------------------------------------------------------------------------
# SSE monitoring
# ---------------------------------------------------------------------------


class StageTimeoutError(Exception):
    def __init__(self, stage: str, elapsed: float):
        super().__init__(f"Stage '{stage}' timed out after {elapsed:.0f}s")
        self.stage = stage
        self.elapsed = elapsed


@dataclass
class PipelineReport:
    completed_stages: list[str] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    stage_durations: dict[str, float] = field(default_factory=dict)
    container_logs_clean: bool = True
    raw_events: list[dict] = field(default_factory=list)


_ERROR_KEYWORDS = ("error", "failed", "exception")


def _check_container_logs(container_name: str, tail: int = 500) -> bool:
    """Return True if no unexpected ERROR/Traceback lines appear in container logs."""
    try:
        result = subprocess.run(
            ["docker", "logs", container_name, "--tail", str(tail)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return True  # can't check, assume clean

    combined = result.stdout + result.stderr
    for line in combined.splitlines():
        if "Traceback (most recent call last)" in line or \
           " ERROR " in line or " CRITICAL " in line:
            if not any(pat in line for pat in LOG_IGNORE_PATTERNS):
                return False
    return True


class SSEMonitor:
    """Drives stage-level e2e assertions by consuming the SSE event stream."""

    def __init__(self):
        self._api_key = _read_api_key()

    async def run(
        self,
        target_id: int,
        worker: str,
        stage_assertions: dict[str, Callable | None],
        stage_timeouts: dict[str, int],
        default_stage_timeout: int = 300,
    ) -> PipelineReport:
        report = PipelineReport()
        event_queue: asyncio.Queue[dict] = asyncio.Queue()

        async def _reader():
            async with httpx.AsyncClient(
                base_url=_BASE_URL,
                headers={"X-API-KEY": self._api_key},
                timeout=httpx.Timeout(None),
            ) as stream_client:
                async with stream_client.stream(
                    "GET", f"/api/v1/stream/{target_id}"
                ) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            try:
                                event = json.loads(line[6:])
                                await event_queue.put(event)
                            except json.JSONDecodeError:
                                pass
            await event_queue.put({"event": "_EOF"})

        assertion_client = httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={"X-API-KEY": self._api_key, "Content-Type": "application/json"},
            timeout=30.0,
        )
        reader_task = asyncio.create_task(_reader())
        try:
            for stage_name, assertion in stage_assertions.items():
                timeout_s = stage_timeouts.get(stage_name, default_stage_timeout)
                stage_start = time.monotonic()

                while True:
                    remaining = timeout_s - (time.monotonic() - stage_start)
                    if remaining <= 0:
                        raise StageTimeoutError(stage_name, time.monotonic() - stage_start)
                    try:
                        event = await asyncio.wait_for(event_queue.get(), timeout=remaining)
                    except asyncio.TimeoutError:
                        raise StageTimeoutError(stage_name, time.monotonic() - stage_start)

                    report.raw_events.append(event)
                    event_type = event.get("event", "")

                    if any(kw in event_type.lower() for kw in _ERROR_KEYWORDS):
                        report.errors.append(event)

                    if event_type == "_EOF":
                        return report

                    if event_type == "STAGE_COMPLETE" and event.get("stage") == stage_name:
                        report.completed_stages.append(stage_name)
                        report.stage_durations[stage_name] = time.monotonic() - stage_start
                        if assertion is not None:
                            await assertion(assertion_client, target_id)
                        break

            # Drain until PIPELINE_COMPLETE (up to 60s)
            try:
                while True:
                    event = await asyncio.wait_for(event_queue.get(), timeout=60)
                    if event.get("event") in ("PIPELINE_COMPLETE", "_EOF"):
                        break
            except asyncio.TimeoutError:
                pass

            report.container_logs_clean = _check_container_logs(worker)
        finally:
            reader_task.cancel()
            try:
                await reader_task
            except (asyncio.CancelledError, Exception):
                pass
            await assertion_client.aclose()

        return report


@pytest.fixture(scope="module")
def sse_monitor():
    return SSEMonitor()


# ---------------------------------------------------------------------------
# HTTP client fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
async def client(stack):
    async with httpx.AsyncClient(
        base_url=_BASE_URL,
        headers={"X-API-KEY": _read_api_key(), "Content-Type": "application/json"},
        timeout=30.0,
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Target helpers
# ---------------------------------------------------------------------------

_DEFAULT_TARGET = "testphp.vulnweb.com"


async def create_target(
    client: httpx.AsyncClient,
    playbook: str,
    company: str,
    domain: str = _DEFAULT_TARGET,
) -> int:
    res = await client.post("/api/v1/targets", json={
        "company_name": company,
        "base_domain": domain,
        "playbook": playbook,
    })
    if res.status_code == 409:
        raise RuntimeError(
            f"409: another target is still active — previous test cleanup may have failed. "
            f"Response: {res.text}"
        )
    assert res.status_code == 201, f"create_target failed: {res.status_code} {res.text}"
    return res.json()["target_id"]


async def cleanup_target(client: httpx.AsyncClient, target_id: int) -> None:
    try:
        res = await client.delete(f"/api/v1/targets/{target_id}")
        if res.status_code not in (200, 204, 404):
            print(f"\nWARNING: cleanup_target({target_id}) returned {res.status_code}: {res.text}")
    except Exception as exc:
        print(f"\nWARNING: cleanup_target({target_id}) raised {exc}")


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


async def assert_assets(
    client: httpx.AsyncClient,
    target_id: int,
    min_count: int = 1,
    asset_type: str | None = None,
) -> list:
    params: dict = {"target_id": target_id}
    if asset_type:
        params["asset_type"] = asset_type
    res = await client.get("/api/v1/assets", params=params)
    assert res.status_code == 200, f"GET /api/v1/assets returned {res.status_code}"
    data = res.json()
    assert data["total"] >= min_count, (
        f"Expected ≥{min_count} assets (asset_type={asset_type!r}) for target {target_id}, "
        f"got {data['total']}"
    )
    return data["assets"]


async def assert_vulnerabilities(
    client: httpx.AsyncClient,
    target_id: int,
    min_count: int = 1,
) -> list:
    res = await client.get("/api/v1/vulnerabilities", params={"target_id": target_id})
    assert res.status_code == 200, f"GET /api/v1/vulnerabilities returned {res.status_code}"
    data = res.json()
    assert data["total"] >= min_count, (
        f"Expected ≥{min_count} vulnerabilities for target {target_id}, got {data['total']}"
    )
    return data["vulnerabilities"]


async def assert_job_completed(
    client: httpx.AsyncClient,
    target_id: int,
    container_name: str,
    last_stage: str,
) -> dict:
    res = await client.get("/api/v1/status", params={"target_id": target_id})
    assert res.status_code == 200
    jobs = res.json()["jobs"]
    job = next((j for j in jobs if j["container_name"] == container_name), None)
    assert job is not None, (
        f"No job_state row found for container '{container_name}', target {target_id}. "
        f"Known containers: {[j['container_name'] for j in jobs]}"
    )
    assert job["status"] == "COMPLETED", (
        f"Expected status=COMPLETED for '{container_name}', got {job['status']}"
    )
    assert job["current_phase"] == last_stage, (
        f"Expected current_phase='{last_stage}' for '{container_name}', "
        f"got '{job['current_phase']}'"
    )
    return job
