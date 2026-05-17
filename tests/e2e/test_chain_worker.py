"""E2E tests for chain_worker (depends on info_gathering findings).

Uses wide_recon so info_gathering populates the DB before chain_worker runs.
The SSEMonitor filters events by stage name — chain_worker stage names are unique
across all workers so interleaved events from other workers are transparently ignored.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "chain_worker"
PLAYBOOK = "wide_recon"
LAST_STAGE = "reporting"

# chain_worker stages only — SSEMonitor ignores events from other workers
STAGE_ASSERTIONS = {
    "data_collection":    None,
    "chain_evaluation":   None,
    "ai_chain_discovery": None,
    "chain_execution":    None,
    "reporting":          None,
}

STAGE_TIMEOUTS = {
    "data_collection":    300,
    "chain_evaluation":   300,
    "ai_chain_discovery": 600,
    "chain_execution":    900,
    "reporting":          300,
}

_INFO_GATHERING_TIMEOUT = 900


async def _wait_for_info_gathering(client, target_id: int, timeout: int = _INFO_GATHERING_TIMEOUT):
    """Poll until info_gathering reaches COMPLETED before chain_worker starts."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        ig_job = next((j for j in jobs if j["container_name"] == "info_gathering"), None)
        if ig_job and ig_job["status"] == "COMPLETED":
            return
        await asyncio.sleep(15)
    raise TimeoutError(f"info_gathering did not complete within {timeout}s (required by chain_worker)")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ChainWorker")
    await _wait_for_info_gathering(client, target_id)
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_chain_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "chain_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_chain_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
