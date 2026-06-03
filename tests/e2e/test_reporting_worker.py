"""E2E tests for reporting_worker (registered as 'reporting' in PIPELINE_STAGES).

Uses wide_recon so prior workers populate findings before reporting runs.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_assets, assert_job_completed, assert_reports,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "reporting_worker"
CONTAINER = "reporting_worker"
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

_PREREQ_TIMEOUT = 4200


async def _wait_for_reasoning_worker(client, target_id: int, timeout: int = _PREREQ_TIMEOUT):
    """Poll until reasoning_worker completes — reporting_worker fires only after that."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        rw = next((j for j in jobs if j["container_name"] == "reasoning_worker"), None)
        if rw and rw["status"] in ("COMPLETED", "SKIPPED"):
            return
        await asyncio.sleep(20)
    raise TimeoutError(f"reasoning_worker did not complete within {timeout}s")


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ReportingWorker", worker=WORKER)
    try:
        await _wait_for_reasoning_worker(client, target_id)
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


async def test_reporting_worker_report_downloadable(client, pipeline_result):
    """Assert all listed report files can be downloaded (HEAD returns 200)."""
    target_id, _ = pipeline_result
    reports = await assert_reports(client, target_id, min_count=1)
    for report in reports:
        filename = report["filename"]
        res = await client.head(f"/api/v1/targets/{target_id}/reports/{filename}")
        assert res.status_code == 200, (
            f"HEAD /api/v1/targets/{target_id}/reports/{filename} returned {res.status_code}"
        )
