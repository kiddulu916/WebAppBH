"""E2E tests for reporting_worker (registered as 'reporting' in PIPELINE_STAGES).

Uses wide_recon so prior workers populate findings before reporting runs.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "reporting"            # playbooks.py key
CONTAINER = "reporting_worker"  # docker container name (used for log fetch)
PLAYBOOK = "wide_recon"
LAST_STAGE = "export"

STAGE_ASSERTIONS = {
    "data_gathering": None,
    "deduplication":  None,
    "rendering":      None,
    "export":         lambda c, tid: assert_assets(c, tid),
}

STAGE_TIMEOUTS = {
    "data_gathering": 180,
    "deduplication":  120,
    "rendering":      300,
    "export":         120,
}

_PREREQ_TIMEOUT = 900


async def _wait_for_info_gathering(client, target_id: int, timeout: int = _PREREQ_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        ig = next((j for j in jobs if j["container_name"] == "info_gathering"), None)
        if ig and ig["status"] == "COMPLETED":
            return
        await asyncio.sleep(15)
    raise TimeoutError(f"info_gathering did not complete within {timeout}s")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ReportingWorker")
    try:
        await _wait_for_info_gathering(client, target_id)
        report = await sse_monitor.run(target_id, CONTAINER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_reporting_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "reporting_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_reporting_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, CONTAINER, LAST_STAGE)
