"""E2E tests for authorization worker (WSTG-ATHZ-01 through ATHZ-04)."""
import pytest
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "authorization"
PLAYBOOK = "e2e_authorization"
LAST_STAGE = "idor"

STAGE_ASSERTIONS = {
    "directory_traversal":  None,
    "authz_bypass":         None,
    "privilege_escalation": None,
    "idor":                 None,  # findings depend on target; stage completion is the invariant
}

STAGE_TIMEOUTS = {
    "directory_traversal":  300,
    "authz_bypass":         300,
    "privilege_escalation": 300,
    "idor":                 300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-Authorization", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_authorization_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "authorization container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_authorization_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_authorization_all_vulns_have_description(client, pipeline_result):
    """Assert every authorization vulnerability has a non-empty description."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "authorization"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    if not vulns:
        return  # no findings on this target — pipeline ran correctly but target is clean
    for v in vulns:
        assert v["description"] is not None and v["description"].strip() != "", (
            f"Vulnerability {v['id']} ({v['title']!r}) has empty description"
        )
