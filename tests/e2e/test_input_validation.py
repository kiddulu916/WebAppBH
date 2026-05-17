"""E2E tests for input_validation worker (WSTG-INPV-01 through INPV-19)."""
import pytest
from conftest import (
    assert_vulnerabilities, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "input_validation"
PLAYBOOK = "e2e_input_validation"
LAST_STAGE = "websocket_injection"

STAGE_ASSERTIONS = {
    "reflected_xss":         lambda c, tid: assert_vulnerabilities(c, tid),
    "stored_xss":            None,
    "http_verb_tampering":   None,
    "http_param_pollution":  None,
    "sql_injection":         lambda c, tid: assert_vulnerabilities(c, tid),
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
    "websocket_injection":   None,
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
    target_id = await create_target(client, PLAYBOOK, "E2E-InputValidation")
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
