"""E2E tests for input_validation worker (WSTG-INPV-01 through INPV-19)."""
import pytest
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "input_validation"
PLAYBOOK = "e2e_input_validation"
LAST_STAGE = "websocket_injection"

STAGE_ASSERTIONS = {
    "reflected_xss":         None,
    "stored_xss":            None,
    "http_verb_tampering":   None,
    "http_param_pollution":  None,
    "sql_injection":         None,
    "ldap_injection":        None,
    "xml_injection":         None,
    "ssti":                  None,
    "xpath_injection":       None,
    "imap_smtp_injection":   None,
    "code_injection":        None,
    "command_injection":     None,
    "format_string":         None,
    "host_header_injection": None,
    "ssrf":                  None,
    "file_inclusion":        None,
    "buffer_overflow":       None,
    "http_smuggling":        None,
    "websocket_injection":   lambda c, tid: assert_vulnerabilities(c, tid),
}

STAGE_TIMEOUTS = {
    "reflected_xss":         600,
    "stored_xss":            600,
    "http_verb_tampering":   300,
    "http_param_pollution":  300,
    "sql_injection":         600,
    "ldap_injection":        300,
    "xml_injection":         300,
    "ssti":                  300,
    "xpath_injection":       300,
    "imap_smtp_injection":   300,
    "code_injection":        300,
    "command_injection":     300,
    "format_string":         300,
    "host_header_injection": 300,
    "ssrf":                  300,
    "file_inclusion":        300,
    "buffer_overflow":       300,
    "http_smuggling":        300,
    "websocket_injection":   300,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-InputValidation", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_input_validation_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "input_validation container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_input_validation_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_input_validation_vuln_types_diverse(client, pipeline_result):
    """Assert input_validation produced ≥2 distinct vuln_type values (multiple tool categories ran)."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "input_validation", "page_size": 500},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No input_validation vulnerabilities found"
    vuln_types = {v["vuln_type"] for v in vulns if v.get("vuln_type")}
    assert len(vuln_types) >= 2, (
        f"Expected ≥2 distinct vuln_type values, got {vuln_types}"
    )
