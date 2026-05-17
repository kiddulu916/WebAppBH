"""E2E tests for identity_mgmt worker (WSTG-IDNT-01 through IDNT-05)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "identity_mgmt"
PLAYBOOK = "e2e_identity_mgmt"
LAST_STAGE = "weak_username_policy"

STAGE_ASSERTIONS = {
    "role_definitions":       lambda c, tid: assert_assets(c, tid),
    "registration_process":   lambda c, tid: assert_assets(c, tid),
    "account_provisioning":   None,
    "account_enumeration":    None,
    "weak_username_policy":   None,
}

STAGE_TIMEOUTS = {
    "role_definitions":       120,
    "registration_process":   120,
    "account_provisioning":   120,
    "account_enumeration":    180,
    "weak_username_policy":   120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-IdentityMgmt")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_identity_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "identity_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_identity_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
