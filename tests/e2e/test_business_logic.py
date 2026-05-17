"""E2E tests for business_logic worker (WSTG-BUSL-01 through BUSL-09)."""
import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "business_logic"
PLAYBOOK = "e2e_business_logic"
LAST_STAGE = "malicious_file_upload"

STAGE_ASSERTIONS = {
    "data_validation":        None,
    "request_forgery":        None,
    "integrity_checks":       None,
    "process_timing":         None,
    "rate_limiting":          None,
    "workflow_bypass":        None,
    "application_misuse":     None,
    "file_upload_validation": None,
    "malicious_file_upload":  None,
}

STAGE_TIMEOUTS = {
    "data_validation":        300,
    "request_forgery":        300,
    "integrity_checks":       300,
    "process_timing":         300,
    "rate_limiting":          300,
    "workflow_bypass":        300,
    "application_misuse":     300,
    "file_upload_validation": 300,
    "malicious_file_upload":  300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-BusinessLogic")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_business_logic_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "business_logic container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_business_logic_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
