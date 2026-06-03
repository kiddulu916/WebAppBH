"""E2E tests for client_side worker (WSTG-CLNT-01 through CLNT-13)."""
import pytest
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "client_side"
PLAYBOOK = "e2e_client_side"
LAST_STAGE = "malicious_upload_client"

STAGE_ASSERTIONS = {
    "dom_xss":                           None,
    "clickjacking":                      None,
    "csrf_tokens":                       None,
    "csp_bypass":                        None,
    "html5_injection":                   None,
    "web_storage":                       None,
    "client_side_logic":                 None,
    "dom_based_injection":               None,
    "client_side_resource_manipulation": None,
    "client_side_auth":                  None,
    "xss_client_side":                   None,
    "css_injection":                     None,
    "malicious_upload_client":           None,  # findings depend on target; stage completion is the invariant
}

STAGE_TIMEOUTS = {
    "dom_xss":                           300,
    "clickjacking":                      120,
    "csrf_tokens":                       120,
    "csp_bypass":                        120,
    "html5_injection":                   120,
    "web_storage":                       120,
    "client_side_logic":                 120,
    "dom_based_injection":               120,
    "client_side_resource_manipulation": 120,
    "client_side_auth":                  120,
    "xss_client_side":                   300,
    "css_injection":                     120,
    "malicious_upload_client":           300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ClientSide", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_client_side_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "client_side container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_client_side_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_client_side_vulns_have_source_tool(client, pipeline_result):
    """Assert every client_side vulnerability records which tool produced it."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "client_side"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    if not vulns:
        return  # no findings on this target — pipeline ran correctly but target is clean
    for v in vulns:
        assert v["source_tool"] is not None and v["source_tool"].strip() != "", (
            f"Client-side vulnerability {v['id']} has null source_tool"
        )
