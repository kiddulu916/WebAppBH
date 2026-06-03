"""E2E tests for cryptography worker (WSTG-CRYP-01 through CRYP-04)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed, assert_vulnerabilities,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "cryptography"
PLAYBOOK = "e2e_cryptography"
LAST_STAGE = "weak_crypto"

STAGE_ASSERTIONS = {
    "tls_testing":            lambda c, tid: assert_assets(c, tid),
    "padding_oracle":         None,
    "plaintext_transmission": None,
    "weak_crypto":            None,  # findings depend on target; stage completion is the invariant
}

STAGE_TIMEOUTS = {
    "tls_testing":            180,
    "padding_oracle":         300,
    "plaintext_transmission": 180,
    "weak_crypto":            180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-Cryptography", worker=WORKER)
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_cryptography_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "cryptography container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_cryptography_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_cryptography_vuln_severity_set(client, pipeline_result):
    """Assert all cryptography vulnerabilities have a non-null severity."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "cryptography"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    if not vulns:
        return  # no findings on this target — pipeline ran correctly but target is clean
    for v in vulns:
        assert v["severity"] is not None and v["severity"] != "", (
            f"Crypto vulnerability {v['id']} has null severity"
        )
