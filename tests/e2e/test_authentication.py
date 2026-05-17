"""E2E tests for authentication worker (WSTG-ATHN-01 through ATHN-10)."""
import pytest
from conftest import (
    assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "authentication"
PLAYBOOK = "e2e_authentication"
LAST_STAGE = "multi_channel_auth"

STAGE_ASSERTIONS = {
    "credentials_transport": None,
    "default_credentials":   None,
    "lockout_mechanism":     None,
    "auth_bypass":           None,
    "remember_password":     None,
    "browser_cache":         None,
    "weak_password_policy":  None,
    "security_questions":    None,
    "password_change":       None,
    "multi_channel_auth":    None,
}

STAGE_TIMEOUTS = {
    "credentials_transport": 120,
    "default_credentials":   300,
    "lockout_mechanism":     180,
    "auth_bypass":           300,
    "remember_password":     120,
    "browser_cache":         120,
    "weak_password_policy":  120,
    "security_questions":    120,
    "password_change":       120,
    "multi_channel_auth":    120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-Authentication")
    report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
    yield target_id, report
    await cleanup_target(client, target_id)


async def test_authentication_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "authentication container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_authentication_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
