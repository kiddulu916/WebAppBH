"""E2E tests for identity_mgmt worker (WSTG-IDNT-01 through IDNT-04)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "identity_mgmt"
PLAYBOOK = "e2e_identity_mgmt"
LAST_STAGE = "account_enumeration"

STAGE_ASSERTIONS = {
    "role_definitions":       None,
    "registration_process":   None,
    "account_provisioning":   None,
    "account_enumeration":    lambda c, tid: assert_assets(c, tid),
}

STAGE_TIMEOUTS = {
    "role_definitions":       120,
    "registration_process":   120,
    "account_provisioning":   120,
    "account_enumeration":    180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-IdentityMgmt", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
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


async def test_identity_mgmt_assets_have_value(client, pipeline_result):
    """Assert identity_mgmt assets all have non-empty asset_value."""
    target_id, _ = pipeline_result
    res = await client.get("/api/v1/assets", params={"target_id": target_id})
    assert res.status_code == 200
    assets = res.json()["assets"]
    assert assets, "No assets found for identity_mgmt target"
    for a in assets:
        assert a["asset_value"] is not None and a["asset_value"].strip() != "", (
            f"Asset {a['id']} has empty asset_value"
        )
