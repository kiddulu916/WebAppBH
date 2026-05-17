"""E2E tests for info_gathering worker (WSTG-INFO-01 through INFO-10)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "info_gathering"
PLAYBOOK = "e2e_info_gathering"
LAST_STAGE = "map_application"

STAGE_ASSERTIONS = {
    "search_engine_recon":    lambda c, tid: assert_assets(c, tid),
    "web_server_fingerprint": lambda c, tid: assert_assets(c, tid),
    "web_server_metafiles":   lambda c, tid: assert_assets(c, tid),
    "enumerate_applications": lambda c, tid: assert_assets(c, tid),
    "review_comments":        None,
    "identify_entry_points":  lambda c, tid: assert_assets(c, tid),
    "aggregate_entry_points": lambda c, tid: assert_assets(c, tid),
    "map_execution_paths":    lambda c, tid: assert_assets(c, tid),
    "review_comments_deep":   None,
    "fingerprint_framework":  lambda c, tid: assert_assets(c, tid),
    "map_architecture":       lambda c, tid: assert_assets(c, tid),
    "map_application":        lambda c, tid: assert_assets(c, tid),
}

STAGE_TIMEOUTS = {
    "search_engine_recon":    180,
    "web_server_fingerprint": 120,
    "web_server_metafiles":   120,
    "enumerate_applications": 180,
    "review_comments":        180,
    "identify_entry_points":  180,
    "aggregate_entry_points": 120,
    "map_execution_paths":    180,
    "review_comments_deep":   180,
    "fingerprint_framework":  120,
    "map_architecture":       120,
    "map_application":        120,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-InfoGathering")
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_info_gathering_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "info_gathering container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_info_gathering_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
