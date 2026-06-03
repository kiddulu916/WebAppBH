"""E2E tests for reasoning_worker (requires Ollama sidecar).

Uses wide_recon so info_gathering findings exist for the LLM to reason about.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "reasoning_worker"
PLAYBOOK = "wide_recon"
LAST_STAGE = "chain_hypothesis"

STAGE_ASSERTIONS = {
    "finding_correlation": None,
    "impact_analysis":     None,
    "chain_hypothesis":    None,
}

STAGE_TIMEOUTS = {
    "finding_correlation": 300,
    "impact_analysis":     300,
    "chain_hypothesis":    600,
}

_PREREQ_TIMEOUT = 3600


async def _wait_for_chain_worker(client, target_id: int, timeout: int = _PREREQ_TIMEOUT):
    """Poll until chain_worker completes — reasoning_worker fires only after that."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        cw = next((j for j in jobs if j["container_name"] == "chain_worker"), None)
        if cw and cw["status"] in ("COMPLETED", "SKIPPED"):
            return
        await asyncio.sleep(20)
    raise TimeoutError(f"chain_worker did not complete within {timeout}s")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ReasoningWorker", worker=WORKER)
    try:
        await _wait_for_chain_worker(client, target_id)
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_reasoning_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "reasoning_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_reasoning_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
