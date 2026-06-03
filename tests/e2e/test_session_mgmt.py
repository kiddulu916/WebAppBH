"""E2E tests for session_mgmt worker (WSTG-SESS-01 through SESS-09)."""
import pytest
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "session_mgmt"
PLAYBOOK = "e2e_session_mgmt"
LAST_STAGE = "session_hijacking"

STAGE_ASSERTIONS = {
    "session_scheme":       None,
    "cookie_attributes":    None,
    "session_fixation":     None,
    "exposed_variables":    None,
    "csrf":                 None,
    "logout_functionality": None,
    "session_timeout":      None,
    "session_puzzling":     None,
    "session_hijacking":    None,  # findings depend on target; stage completion is the invariant
}

STAGE_TIMEOUTS = {
    "session_scheme":       180,
    "cookie_attributes":    120,
    "session_fixation":     180,
    "exposed_variables":    120,
    "csrf":                 120,
    "logout_functionality": 120,
    "session_timeout":      120,
    "session_puzzling":     120,
    "session_hijacking":    180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-SessionMgmt", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_session_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "session_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_session_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_session_mgmt_vulns_have_source_tool(client, pipeline_result):
    """Assert every session_mgmt vulnerability records which tool found it."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "session_mgmt"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    if not vulns:
        return  # no findings on this target — pipeline ran correctly but target is clean
    for v in vulns:
        assert v["source_tool"] is not None and v["source_tool"].strip() != "", (
            f"Vulnerability {v['id']} has null source_tool"
        )
