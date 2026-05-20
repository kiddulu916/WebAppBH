"""E2E tests for config_mgmt worker (WSTG-CONF-01 through CONF-11)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "config_mgmt"
PLAYBOOK = "e2e_config_mgmt"
LAST_STAGE = "cloud_storage"

STAGE_ASSERTIONS = {
    "network_config":               lambda c, tid: assert_assets(c, tid),
    "network_config_cred_test":     None,
    "platform_config":              lambda c, tid: assert_assets(c, tid),
    "file_extension_handling":      lambda c, tid: assert_assets(c, tid),
    "backup_files":                 None,
    "admin_interface_enumeration":  None,
    "api_discovery":                lambda c, tid: assert_assets(c, tid),
    "http_methods":                 lambda c, tid: assert_assets(c, tid),
    "hsts_testing":                 None,
    "rpc_testing":                  None,
    "file_permission":              None,
    "file_inclusion":               None,
    "subdomain_takeover":           None,
    "cloud_storage":                None,
}

STAGE_TIMEOUTS = {
    "network_config":               600,
    "network_config_cred_test":     300,
    "platform_config":              120,
    "file_extension_handling":      120,
    "backup_files":                 120,
    "admin_interface_enumeration":  300,
    "api_discovery":                180,
    "http_methods":                 120,
    "hsts_testing":                 120,
    "rpc_testing":                  120,
    "file_permission":              120,
    "file_inclusion":               120,
    "subdomain_takeover":           180,
    "cloud_storage":                180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ConfigMgmt")
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_config_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "config_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_config_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
