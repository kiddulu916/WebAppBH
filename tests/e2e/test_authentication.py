"""E2E tests for authentication worker (WSTG-ATHN-02 through ATHN-10)."""
import pytest
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "authentication"
PLAYBOOK = "e2e_authentication"
LAST_STAGE = "multi_channel_auth"


async def _assert_auth_bypass(client, target_id):
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "authentication"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    bypass_vulns = [v for v in vulns if v.get("source_tool") == "auth_bypass_tester"]
    assert len(bypass_vulns) >= 1, (
        f"Expected at least 1 Vulnerability from auth_bypass_tester, got {len(bypass_vulns)}"
    )


STAGE_ASSERTIONS = {
    "default_credentials":   None,
    "lockout_mechanism":     None,
    "auth_bypass":           _assert_auth_bypass,
    "remember_password":     None,
    "browser_cache":         None,
    "weak_password_policy":  None,
    "security_questions":    None,
    "password_change":       None,
    "multi_channel_auth":    None,  # findings depend on target; stage completion is the invariant
}

STAGE_TIMEOUTS = {
    "default_credentials":   600,
    "lockout_mechanism":     1050,
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
    target_id = await create_target(client, PLAYBOOK, "E2E-Authentication", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
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


async def test_authentication_all_vulns_have_severity(client, pipeline_result):
    """Assert every vulnerability from authentication has a non-null severity."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "authentication"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    if not vulns:
        return  # no findings on this target — pipeline ran correctly but target is clean
    for v in vulns:
        assert v["severity"] is not None and v["severity"] != "", (
            f"Vulnerability {v['id']} ({v['title']!r}) has null/empty severity"
        )
