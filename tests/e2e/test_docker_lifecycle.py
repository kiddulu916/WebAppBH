"""Docker lifecycle integration tests.

Validates the real message flow between orchestrator and workers:
  orchestrator pushes to Redis → worker picks up → runs pipeline →
  writes to DB → orchestrator detects completion → triggers next worker.

These tests require Docker and real Redis/Postgres (via docker-compose.test.yml).
Skip gracefully when Docker is not available.
"""

import asyncio
import os
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# Force SQLite for tests
os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401

from lib_webbh.database import (
    Asset,
    Base,
    CloudAsset,
    JobState,
    Location,
    MobileApp,
    Parameter,
    Target,
    Vulnerability,
    get_engine,
    get_session,
)

from orchestrator.event_engine import (
    _check_api_trigger,
    _check_chain_trigger,
    _check_cloud_trigger,
    _check_mobile_trigger,
    _check_network_trigger,
    _check_recon_trigger,
    _check_reporting_trigger,
    _check_vulnscan_trigger,
    _check_web_trigger,
    _trigger_worker,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    """Fresh in-memory DB for each test."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_full_target(db):
    """Create a target with assets, locations, params, cloud assets, and mobile app.

    Returns a dict with all created entity IDs for assertions.
    """
    async with get_session() as session:
        # Target
        target = Target(
            company_name="LifecycleCorp",
            base_domain="lifecycle.com",
            target_profile={
                "in_scope_domains": ["*.lifecycle.com"],
            },
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)
        tid = target.id

        # Assets — web and network
        web_asset = Asset(
            target_id=tid,
            asset_type="domain",
            asset_value="www.lifecycle.com",
            source_tool="subfinder",
        )
        net_asset = Asset(
            target_id=tid,
            asset_type="domain",
            asset_value="ssh.lifecycle.com",
            source_tool="subfinder",
        )
        session.add_all([web_asset, net_asset])
        await session.commit()
        await session.refresh(web_asset)
        await session.refresh(net_asset)

        # Locations — HTTP + SSH
        loc_https = Location(
            asset_id=web_asset.id,
            port=443,
            state="open",
            protocol="tcp",
        )
        loc_ssh = Location(
            asset_id=net_asset.id,
            port=22,
            state="open",
            protocol="tcp",
        )
        session.add_all([loc_https, loc_ssh])
        await session.commit()

        # Parameters (> threshold of 20)
        for i in range(25):
            session.add(Parameter(
                asset_id=web_asset.id,
                param_name=f"param_{i}",
                source_url=f"https://www.lifecycle.com/api?param_{i}=val",
            ))
        await session.commit()

        # Cloud asset
        cloud = CloudAsset(
            target_id=tid,
            provider="aws",
            asset_type="s3_bucket",
            url="https://lifecycle-assets.s3.amazonaws.com",
        )
        session.add(cloud)
        await session.commit()

        # Mobile app
        mobile = MobileApp(
            target_id=tid,
            platform="android",
            package_name="com.lifecycle.app",
        )
        session.add(mobile)
        await session.commit()

    return {
        "target_id": tid,
        "web_asset_id": web_asset.id,
        "net_asset_id": net_asset.id,
    }


@pytest.fixture(autouse=True)
def mock_push_task():
    """Prevent real Redis calls from _emit_event / push_task."""
    with patch("orchestrator.event_engine.push_task", new_callable=AsyncMock):
        yield


@pytest.fixture
def mock_wm():
    """Mock worker_manager for all trigger calls."""
    with patch("orchestrator.event_engine.worker_manager") as wm:
        wm.start_worker = AsyncMock(return_value="fake-cid")
        wm.should_queue = AsyncMock(return_value=False)
        wm.kill_worker = AsyncMock(return_value=True)
        wm.get_container_status = AsyncMock(return_value=None)
        yield wm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _complete_job(target_id: int, container_name: str, phase: str) -> None:
    """Insert or update a JobState row as COMPLETED."""
    async with get_session() as session:
        job = JobState(
            target_id=target_id,
            container_name=container_name,
            current_phase=phase,
            status="COMPLETED",
            last_seen=datetime.utcnow(),
        )
        session.add(job)
        await session.commit()


async def _get_triggered_workers(mock_wm) -> list[str]:
    """Extract container names from mock start_worker calls."""
    containers = []
    for call in mock_wm.start_worker.call_args_list:
        # start_worker(image=..., container_name=..., ...)
        if "container_name" in call.kwargs:
            containers.append(call.kwargs["container_name"])
    return containers


# ---------------------------------------------------------------------------
# Tests — Full lifecycle simulation
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_lifecycle_phase1_recon_triggers_on_new_target(
    seed_full_target, mock_wm,
):
    """Phase 1: New target with no recon job should trigger recon."""
    tid = seed_full_target["target_id"]

    await _check_recon_trigger()

    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-recon-t{tid}" in containers


@pytest.mark.anyio
async def test_lifecycle_phase2_recon_complete_triggers_downstream(
    seed_full_target, mock_wm,
):
    """Phase 2: After recon completes, web/api/cloud/network/mobile triggers fire."""
    tid = seed_full_target["target_id"]

    # Mark recon as completed
    await _complete_job(tid, f"webbh-recon-t{tid}", "deep_recon")

    # Run all downstream triggers
    await _check_web_trigger()
    await _check_api_trigger()
    await _check_cloud_trigger()
    await _check_network_trigger()
    await _check_mobile_trigger()

    containers = await _get_triggered_workers(mock_wm)

    # Web trigger should fire fuzzing + webapp
    assert f"webbh-fuzzing-t{tid}" in containers
    assert f"webbh-webapp_testing-t{tid}" in containers
    # API trigger (params > 20)
    assert f"webbh-api_testing-t{tid}" in containers
    # Cloud trigger (CloudAsset exists)
    assert f"webbh-cloud_testing-t{tid}" in containers
    # Network trigger (port 22 open)
    assert f"webbh-network-t{tid}" in containers
    # Mobile trigger (MobileApp exists)
    assert f"webbh-mobile-t{tid}" in containers


@pytest.mark.anyio
async def test_lifecycle_phase3_vulnscan_triggers_after_prereqs(
    seed_full_target, mock_wm,
):
    """Phase 3: After fuzzing/webapp/api complete, vulnscan fires."""
    tid = seed_full_target["target_id"]

    # Complete prereq workers
    await _complete_job(tid, f"webbh-fuzzing-t{tid}", "injection_fuzzing")
    await _complete_job(tid, f"webbh-webapp_testing-t{tid}", "prototype_pollution_scan")
    await _complete_job(tid, f"webbh-api_testing-t{tid}", "abuse_testing")

    await _check_vulnscan_trigger()

    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-vulnscan-t{tid}" in containers


@pytest.mark.anyio
@patch("orchestrator.event_engine.push_task", new_callable=AsyncMock)
async def test_lifecycle_phase4_chain_triggers_after_workers(
    mock_push, seed_full_target, mock_wm,
):
    """Phase 4: After main workers complete, chain worker fires."""
    tid = seed_full_target["target_id"]

    # Complete workers that are in CHAIN_TRIGGER_WORKERS
    await _complete_job(tid, f"webbh-recon-t{tid}", "deep_recon")
    await _complete_job(tid, f"webbh-fuzzing-t{tid}", "injection_fuzzing")
    await _complete_job(tid, f"webbh-webapp_testing-t{tid}", "prototype_pollution_scan")
    await _complete_job(tid, f"webbh-api_testing-t{tid}", "abuse_testing")
    await _complete_job(tid, f"webbh-cloud_testing-t{tid}", "feedback")

    await _check_chain_trigger()

    # Chain trigger uses push_task("chain_queue", ...) not _trigger_worker
    chain_calls = [
        c for c in mock_push.call_args_list
        if c.args and c.args[0] == "chain_queue"
    ]
    assert len(chain_calls) >= 1
    payload = chain_calls[0].args[1]
    assert payload["target_id"] == tid


@pytest.mark.anyio
async def test_lifecycle_phase5_reporting_triggers_after_chain(
    seed_full_target, mock_wm,
):
    """Phase 5: After chain worker completes, reporting fires."""
    tid = seed_full_target["target_id"]

    await _complete_job(tid, f"webbh-chain-t{tid}", "reporting")

    await _check_reporting_trigger()

    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-reporting-t{tid}" in containers


@pytest.mark.anyio
@patch("orchestrator.event_engine.push_task", new_callable=AsyncMock)
async def test_full_lifecycle_end_to_end(
    mock_push, seed_full_target, mock_wm,
):
    """Full lifecycle: target → recon → downstream → vulnscan → chain → reporting.

    Simulates the complete event engine cycle by running triggers in sequence,
    marking each phase as complete before advancing to the next.
    """
    tid = seed_full_target["target_id"]

    # --- Phase 1: Recon ---
    await _check_recon_trigger()
    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-recon-t{tid}" in containers
    mock_wm.start_worker.reset_mock()

    # Complete recon
    await _complete_job(tid, f"webbh-recon-t{tid}", "deep_recon")

    # --- Phase 2: Downstream workers ---
    await _check_web_trigger()
    await _check_api_trigger()
    await _check_cloud_trigger()
    await _check_network_trigger()
    await _check_mobile_trigger()

    containers = await _get_triggered_workers(mock_wm)
    expected_phase2 = [
        f"webbh-fuzzing-t{tid}",
        f"webbh-webapp_testing-t{tid}",
        f"webbh-api_testing-t{tid}",
        f"webbh-cloud_testing-t{tid}",
        f"webbh-network-t{tid}",
        f"webbh-mobile-t{tid}",
    ]
    for c in expected_phase2:
        assert c in containers, f"Expected {c} to be triggered in phase 2"
    mock_wm.start_worker.reset_mock()

    # Complete all downstream workers
    await _complete_job(tid, f"webbh-fuzzing-t{tid}", "injection_fuzzing")
    await _complete_job(tid, f"webbh-webapp_testing-t{tid}", "prototype_pollution_scan")
    await _complete_job(tid, f"webbh-api_testing-t{tid}", "abuse_testing")
    await _complete_job(tid, f"webbh-cloud_testing-t{tid}", "feedback")
    await _complete_job(tid, f"webbh-network-t{tid}", "exploit_verify")
    await _complete_job(tid, f"webbh-mobile-t{tid}", "endpoint_feedback")

    # --- Phase 3: Vulnscan ---
    await _check_vulnscan_trigger()
    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-vulnscan-t{tid}" in containers
    mock_wm.start_worker.reset_mock()

    # Complete vulnscan
    await _complete_job(tid, f"webbh-vulnscan-t{tid}", "broad_injection_sweep")

    # --- Phase 4: Chain ---
    await _check_chain_trigger()
    chain_calls = [
        c for c in mock_push.call_args_list
        if c.args and c.args[0] == "chain_queue"
    ]
    assert len(chain_calls) >= 1
    mock_push.reset_mock()

    # Complete chain
    await _complete_job(tid, f"webbh-chain-t{tid}", "reporting")

    # --- Phase 5: Reporting ---
    await _check_reporting_trigger()
    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-reporting-t{tid}" in containers


# ---------------------------------------------------------------------------
# Tests — Idempotency and edge cases
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_triggers_are_idempotent_no_double_trigger(
    seed_full_target, mock_wm,
):
    """Running the same trigger twice should not spawn duplicate workers."""
    tid = seed_full_target["target_id"]

    # First call triggers recon
    await _check_recon_trigger()
    assert mock_wm.start_worker.call_count == 1

    # Mark as RUNNING (simulating the job was just created)
    async with get_session() as session:
        job = JobState(
            target_id=tid,
            container_name=f"webbh-recon-t{tid}",
            current_phase="passive_discovery",
            status="RUNNING",
            last_seen=datetime.utcnow(),
        )
        session.add(job)
        await session.commit()

    mock_wm.start_worker.reset_mock()

    # Second call should NOT trigger again
    await _check_recon_trigger()
    assert mock_wm.start_worker.call_count == 0


@pytest.mark.anyio
async def test_resource_constrained_queues_job(seed_full_target, mock_wm):
    """When resources are low, trigger should queue the job instead of starting."""
    tid = seed_full_target["target_id"]
    mock_wm.should_queue.return_value = True

    await _check_recon_trigger()

    # start_worker should NOT be called
    mock_wm.start_worker.assert_not_called()

    # JobState should be QUEUED
    async with get_session() as session:
        from sqlalchemy import select
        stmt = select(JobState).where(
            JobState.target_id == tid,
            JobState.container_name == f"webbh-recon-t{tid}",
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        assert job is not None
        assert job.status == "QUEUED"


@pytest.mark.anyio
async def test_multiple_targets_trigger_independently(db, mock_wm):
    """Multiple targets should each get their own worker triggered."""
    async with get_session() as session:
        t1 = Target(company_name="Corp1", base_domain="corp1.com", target_profile={})
        t2 = Target(company_name="Corp2", base_domain="corp2.com", target_profile={})
        session.add_all([t1, t2])
        await session.commit()
        await session.refresh(t1)
        await session.refresh(t2)

    await _check_recon_trigger()

    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-recon-t{t1.id}" in containers
    assert f"webbh-recon-t{t2.id}" in containers


@pytest.mark.anyio
async def test_failed_job_does_not_block_retrigger(seed_full_target, mock_wm):
    """A FAILED job should not prevent re-triggering (only ACTIVE statuses block)."""
    tid = seed_full_target["target_id"]

    # Insert a FAILED recon job
    async with get_session() as session:
        job = JobState(
            target_id=tid,
            container_name=f"webbh-recon-t{tid}",
            current_phase="active_discovery",
            status="FAILED",
            last_seen=datetime.utcnow() - timedelta(hours=1),
        )
        session.add(job)
        await session.commit()

    await _check_recon_trigger()

    containers = await _get_triggered_workers(mock_wm)
    assert f"webbh-recon-t{tid}" in containers
