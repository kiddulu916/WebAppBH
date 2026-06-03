"""E2E tests for error_handling worker (WSTG-ERRH-01 through ERRH-02)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed, assert_vulnerabilities,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "error_handling"
PLAYBOOK = "e2e_error_handling"
LAST_STAGE = "stack_traces"

STAGE_ASSERTIONS = {
    "error_codes":  lambda c, tid: assert_assets(c, tid),
    "stack_traces": lambda c, tid: assert_vulnerabilities(c, tid),
}

STAGE_TIMEOUTS = {
    "error_codes":  120,
    "stack_traces": 120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ErrorHandling", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_error_handling_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "error_handling container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_error_handling_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_error_handling_vulns_have_poc(client, pipeline_result):
    """Assert error_handling vulnerabilities include evidence (poc field non-null)."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "error_handling"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No error_handling vulnerabilities found"
    vulns_with_poc = [v for v in vulns if v.get("poc")]
    assert len(vulns_with_poc) > 0, (
        "At least one error_handling vulnerability should have a poc/evidence field"
    )
