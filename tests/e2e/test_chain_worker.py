"""E2E tests for chain_worker (depends on info_gathering findings).

Uses wide_recon so info_gathering populates the DB before chain_worker runs.
The SSEMonitor filters events by stage name — chain_worker stage names are unique
across all workers so interleaved events from other workers are transparently ignored.
"""
import asyncio
import time

import pytest
from conftest import (
    assert_chain_findings, assert_job_completed, cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "chain_worker"
PLAYBOOK = "wide_recon"
LAST_STAGE = "reporting"

# chain_worker stages only — SSEMonitor ignores events from other workers
STAGE_ASSERTIONS = {
    "data_collection":    None,
    "chain_evaluation":   None,
    "ai_chain_discovery": None,
    "chain_execution":    None,
    "reporting":          lambda c, tid: assert_chain_findings(tid),
}

STAGE_TIMEOUTS = {
    "data_collection":    300,
    "chain_evaluation":   300,
    "ai_chain_discovery": 600,
    "chain_execution":    900,
    "reporting":          300,
}

_PREREQ_TIMEOUT = 3600

# chain_worker fires only after all five of these complete
_CHAIN_PREREQUISITES = {
    "input_validation", "error_handling",
    "cryptography", "business_logic", "client_side",
}


async def _wait_for_chain_prerequisites(
    client, target_id: int, timeout: int = _PREREQ_TIMEOUT
):
    """Poll until all chain_worker prerequisites reach COMPLETED or SKIPPED."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        done = {
            j["container_name"]
            for j in jobs
            if j["status"] in ("COMPLETED", "SKIPPED")
        }
        if _CHAIN_PREREQUISITES.issubset(done):
            return
        await asyncio.sleep(20)
    raise TimeoutError(
        f"chain_worker prerequisites did not complete within {timeout}s"
    )


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ChainWorker", worker=WORKER)
    try:
        await _wait_for_chain_prerequisites(client, target_id)
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_chain_worker_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "chain_worker container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_chain_worker_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)


async def test_chain_worker_findings_have_severity(pipeline_result):
    """Assert all chain findings have a non-null severity value."""
    target_id, _ = pipeline_result
    from lib_webbh import get_session, ChainFinding
    from sqlalchemy import select

    async with get_session() as session:
        result = await session.execute(
            select(ChainFinding).where(ChainFinding.target_id == target_id)
        )
        findings = result.scalars().all()

    assert findings, "No chain findings — chain_worker did not produce results"
    for f in findings:
        assert f.severity is not None and str(f.severity).strip() != "", (
            f"ChainFinding {f.id} has null or empty severity"
        )
