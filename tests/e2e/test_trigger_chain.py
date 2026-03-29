"""End-to-end tests for the event_engine worker trigger chain.

Validates every ``_check_*_trigger`` function in ``orchestrator.event_engine``
using a real SQLite in-memory database and mocked worker_manager / push_task.

Seeds specific DB state, invokes trigger functions, and asserts that the
correct workers are started (or not) based on the current data.
"""

import os

# Force SQLite in-memory DB before any lib_webbh import.
os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401 — must be imported before orchestrator modules

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, call, patch

import pytest
import pytest_asyncio

from lib_webbh.database import (
    Asset,
    Base,
    CloudAsset,
    JobState,
    Location,
    MobileApp,
    Parameter,
    Target,
    get_engine,
    get_session,
)

from orchestrator.event_engine import (
    WORKER_IMAGES,
    _check_api_trigger,
    _check_chain_trigger,
    _check_cloud_trigger,
    _check_mobile_trigger,
    _check_network_trigger,
    _check_recon_trigger,
    _check_reporting_trigger,
    _check_vulnscan_trigger,
    _check_web_trigger,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    """Create all tables in a fresh SQLite in-memory DB."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    """Insert a target and return its ID."""
    async with get_session() as session:
        t = Target(
            company_name="TestCorp",
            base_domain="testcorp.com",
            target_profile={},
        )
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def mock_wm():
    """Patch worker_manager inside event_engine so no Docker calls are made."""
    with patch("orchestrator.event_engine.worker_manager") as wm:
        wm.start_worker = AsyncMock(return_value="fake-cid")
        wm.should_queue = AsyncMock(return_value=False)
        wm.kill_worker = AsyncMock(return_value=True)
        wm.get_container_status = AsyncMock(return_value=None)
        yield wm


@pytest.fixture
def mock_push():
    """Patch push_task inside event_engine so no Redis calls are made."""
    with patch("orchestrator.event_engine.push_task", new_callable=AsyncMock) as pt:
        yield pt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _old() -> datetime:
    """Return a date far in the past (useful for 'completed before' states)."""
    return datetime(2020, 1, 1, tzinfo=timezone.utc)


def _container(worker_key: str, target_id: int) -> str:
    """Construct the canonical container name."""
    return f"webbh-{worker_key}-t{target_id}"


# ---------------------------------------------------------------------------
# 1. Recon trigger — fires for new targets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recon_trigger_fires_for_new_target(seed_target, mock_wm, mock_push):
    """A target with no recon jobs at all should trigger recon worker."""
    await _check_recon_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["recon"]
    assert call_kwargs.kwargs["container_name"] == _container("recon", seed_target)


# ---------------------------------------------------------------------------
# 2. Recon trigger — skips target with active recon job
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recon_trigger_skips_active_target(seed_target, mock_wm, mock_push):
    """A target with a RUNNING recon job should NOT be re-triggered."""
    async with get_session() as session:
        job = JobState(
            target_id=seed_target,
            container_name=_container("recon", seed_target),
            current_phase="passive_discovery",
            status="RUNNING",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_recon_trigger()

    mock_wm.start_worker.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Cloud trigger — fires on new cloud assets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cloud_trigger_fires_on_new_cloud_assets(seed_target, mock_wm, mock_push):
    """A CloudAsset record newer than any completed cloud job should trigger cloud_testing."""
    async with get_session() as session:
        ca = CloudAsset(
            target_id=seed_target,
            provider="aws",
            asset_type="s3_bucket",
            url="s3://testcorp-data",
        )
        session.add(ca)
        await session.commit()

    await _check_cloud_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["cloud_testing"]
    assert call_kwargs.kwargs["container_name"] == _container("cloud_testing", seed_target)


# ---------------------------------------------------------------------------
# 4. Web trigger — fires on open HTTP ports (both fuzzing AND webapp_testing)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_web_trigger_fires_on_open_http_ports(seed_target, mock_wm, mock_push):
    """An open port 443 should trigger both fuzzing and webapp_testing workers."""
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target,
            asset_type="ip",
            asset_value="10.0.0.1",
            source_tool="nmap",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id,
            port=443,
            protocol="tcp",
            service="https",
            state="open",
        )
        session.add(loc)
        await session.commit()

    await _check_web_trigger()

    # Both fuzzing and webapp_testing should have been started.
    assert mock_wm.start_worker.call_count == 2

    images_started = {c.kwargs["image"] for c in mock_wm.start_worker.call_args_list}
    assert WORKER_IMAGES["fuzzing"] in images_started
    assert WORKER_IMAGES["webapp_testing"] in images_started

    containers_started = {c.kwargs["container_name"] for c in mock_wm.start_worker.call_args_list}
    assert _container("fuzzing", seed_target) in containers_started
    assert _container("webapp_testing", seed_target) in containers_started


# ---------------------------------------------------------------------------
# 5. API trigger — fires when param count exceeds threshold
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_trigger_fires_on_param_threshold(seed_target, mock_wm, mock_push):
    """25 parameters (> 20 threshold) should trigger api_testing."""
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target,
            asset_type="url",
            asset_value="https://testcorp.com/api",
            source_tool="paramspider",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        for i in range(25):
            param = Parameter(
                asset_id=asset.id,
                param_name=f"param_{i}",
                param_value=f"value_{i}",
                source_url=f"https://testcorp.com/api?param_{i}=value_{i}",
            )
            session.add(param)
        await session.commit()

    await _check_api_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["api_testing"]
    assert call_kwargs.kwargs["container_name"] == _container("api_testing", seed_target)


# ---------------------------------------------------------------------------
# 6. Network trigger — fires on non-web open ports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_trigger_fires_on_non_web_ports(seed_target, mock_wm, mock_push):
    """An open port 22 (SSH) should trigger network worker."""
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target,
            asset_type="ip",
            asset_value="10.0.0.5",
            source_tool="masscan",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id,
            port=22,
            protocol="tcp",
            service="ssh",
            state="open",
        )
        session.add(loc)
        await session.commit()

    await _check_network_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["network"]
    assert call_kwargs.kwargs["container_name"] == _container("network", seed_target)


# ---------------------------------------------------------------------------
# 7. Mobile trigger — fires when MobileApp records exist
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mobile_trigger_fires_on_mobile_apps(seed_target, mock_wm, mock_push):
    """A MobileApp record with no active mobile job should trigger mobile worker."""
    async with get_session() as session:
        app = MobileApp(
            target_id=seed_target,
            platform="android",
            package_name="com.testcorp.app",
        )
        session.add(app)
        await session.commit()

    await _check_mobile_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["mobile"]
    assert call_kwargs.kwargs["container_name"] == _container("mobile", seed_target)


# ---------------------------------------------------------------------------
# 8. Vulnscan trigger — fires after fuzzing/webapp/api prerequisite completes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vulnscan_trigger_fires_after_prereqs(seed_target, mock_wm, mock_push):
    """A completed fuzzing job (newer than any vulnscan) should trigger vulnscan."""
    async with get_session() as session:
        job = JobState(
            target_id=seed_target,
            container_name=_container("fuzzing", seed_target),
            current_phase="fuzzing",
            status="COMPLETED",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_vulnscan_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["vulnscan"]
    assert call_kwargs.kwargs["container_name"] == _container("vulnscan", seed_target)


# ---------------------------------------------------------------------------
# 9. Chain trigger — fires after chain-trigger workers complete
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_trigger_fires_after_worker_completion(seed_target, mock_wm, mock_push):
    """A completed recon job newer than any chain job should fire chain trigger via push_task."""
    async with get_session() as session:
        job = JobState(
            target_id=seed_target,
            container_name=_container("recon", seed_target),
            current_phase="passive_discovery",
            status="COMPLETED",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_chain_trigger()

    # Chain trigger uses push_task("chain_queue", ...) not start_worker.
    mock_wm.start_worker.assert_not_called()

    chain_calls = [
        c for c in mock_push.call_args_list
        if c.args[0] == "chain_queue"
    ]
    assert len(chain_calls) == 1
    payload = chain_calls[0].args[1]
    assert payload["target_id"] == seed_target
    assert payload["trigger_phase"] == "recon"
    assert "run_id" in payload


# ---------------------------------------------------------------------------
# 10. Reporting trigger — fires after chain worker completes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reporting_trigger_fires_after_chain(seed_target, mock_wm, mock_push):
    """A completed chain job newer than any reporting job should trigger reporting."""
    async with get_session() as session:
        job = JobState(
            target_id=seed_target,
            container_name=_container("chain", seed_target),
            current_phase="chain",
            status="COMPLETED",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_reporting_trigger()

    mock_wm.start_worker.assert_called_once()
    call_kwargs = mock_wm.start_worker.call_args
    assert call_kwargs.kwargs["image"] == WORKER_IMAGES["reporting"]
    assert call_kwargs.kwargs["container_name"] == _container("reporting", seed_target)


# ---------------------------------------------------------------------------
# 11. Full trigger chain sequence — end-to-end lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_trigger_chain_sequence(db, mock_wm, mock_push):
    """Comprehensive test simulating the full lifecycle:

    1. Create target -> trigger recon
    2. Mark recon complete, seed open ports + params + cloud assets + mobile app
    3. Run all triggers -> assert correct workers triggered in correct order
    """
    # --- Phase 1: Create target, only recon should fire ---
    async with get_session() as session:
        target = Target(
            company_name="FullChainCorp",
            base_domain="fullchain.io",
            target_profile={},
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)
        tid = target.id

    await _check_recon_trigger()
    assert mock_wm.start_worker.call_count == 1
    recon_call = mock_wm.start_worker.call_args
    assert recon_call.kwargs["image"] == WORKER_IMAGES["recon"]
    assert recon_call.kwargs["container_name"] == _container("recon", tid)

    # No other triggers should fire yet — no data exists.
    mock_wm.start_worker.reset_mock()
    mock_push.reset_mock()

    await _check_cloud_trigger()
    await _check_web_trigger()
    await _check_api_trigger()
    await _check_network_trigger()
    await _check_mobile_trigger()
    await _check_vulnscan_trigger()
    await _check_chain_trigger()
    await _check_reporting_trigger()

    assert mock_wm.start_worker.call_count == 0
    # chain_queue should not have been called either
    chain_calls = [c for c in mock_push.call_args_list if c.args and c.args[0] == "chain_queue"]
    assert len(chain_calls) == 0

    # --- Phase 2: Mark recon complete, seed discovery data ---
    now = _now()

    async with get_session() as session:
        # Mark recon as completed
        recon_job = JobState(
            target_id=tid,
            container_name=_container("recon", tid),
            current_phase="passive_discovery",
            status="COMPLETED",
            last_seen=now,
        )
        session.add(recon_job)
        await session.commit()

        # Seed an asset with an open web port (443)
        web_asset = Asset(
            target_id=tid,
            asset_type="ip",
            asset_value="10.0.0.10",
            source_tool="nmap",
        )
        session.add(web_asset)
        await session.commit()
        await session.refresh(web_asset)

        web_loc = Location(
            asset_id=web_asset.id,
            port=443,
            protocol="tcp",
            service="https",
            state="open",
        )
        session.add(web_loc)
        await session.commit()

        # Seed an asset with a non-web port (22)
        ssh_asset = Asset(
            target_id=tid,
            asset_type="ip",
            asset_value="10.0.0.11",
            source_tool="masscan",
        )
        session.add(ssh_asset)
        await session.commit()
        await session.refresh(ssh_asset)

        ssh_loc = Location(
            asset_id=ssh_asset.id,
            port=22,
            protocol="tcp",
            service="ssh",
            state="open",
        )
        session.add(ssh_loc)
        await session.commit()

        # Seed 25 parameters (above the 20-param threshold)
        param_asset = Asset(
            target_id=tid,
            asset_type="url",
            asset_value="https://fullchain.io/api",
            source_tool="paramspider",
        )
        session.add(param_asset)
        await session.commit()
        await session.refresh(param_asset)

        for i in range(25):
            session.add(Parameter(
                asset_id=param_asset.id,
                param_name=f"p{i}",
                param_value=f"v{i}",
                source_url=f"https://fullchain.io/api?p{i}=v{i}",
            ))
        await session.commit()

        # Seed a cloud asset
        session.add(CloudAsset(
            target_id=tid,
            provider="aws",
            asset_type="s3_bucket",
            url="s3://fullchain-data",
        ))
        await session.commit()

        # Seed a mobile app
        session.add(MobileApp(
            target_id=tid,
            platform="android",
            package_name="io.fullchain.app",
        ))
        await session.commit()

    # --- Phase 3: Run all triggers and verify ---
    mock_wm.start_worker.reset_mock()
    mock_push.reset_mock()

    # Recon should NOT fire again (target already has COMPLETED recon job).
    await _check_recon_trigger()
    assert mock_wm.start_worker.call_count == 0

    # Cloud trigger: should fire (new cloud asset, no prior cloud job).
    mock_wm.start_worker.reset_mock()
    await _check_cloud_trigger()
    assert mock_wm.start_worker.call_count == 1
    assert mock_wm.start_worker.call_args.kwargs["image"] == WORKER_IMAGES["cloud_testing"]

    # Web trigger: should fire fuzzing + webapp_testing (open port 443).
    mock_wm.start_worker.reset_mock()
    await _check_web_trigger()
    assert mock_wm.start_worker.call_count == 2
    web_images = {c.kwargs["image"] for c in mock_wm.start_worker.call_args_list}
    assert WORKER_IMAGES["fuzzing"] in web_images
    assert WORKER_IMAGES["webapp_testing"] in web_images

    # API trigger: should fire (25 params > 20 threshold).
    mock_wm.start_worker.reset_mock()
    await _check_api_trigger()
    assert mock_wm.start_worker.call_count == 1
    assert mock_wm.start_worker.call_args.kwargs["image"] == WORKER_IMAGES["api_testing"]

    # Network trigger: should fire (open port 22, no active/completed network job).
    mock_wm.start_worker.reset_mock()
    await _check_network_trigger()
    assert mock_wm.start_worker.call_count == 1
    assert mock_wm.start_worker.call_args.kwargs["image"] == WORKER_IMAGES["network"]

    # Mobile trigger: should fire (MobileApp exists, no active/completed mobile job).
    mock_wm.start_worker.reset_mock()
    await _check_mobile_trigger()
    assert mock_wm.start_worker.call_count == 1
    assert mock_wm.start_worker.call_args.kwargs["image"] == WORKER_IMAGES["mobile"]

    # Vulnscan trigger: should NOT fire yet (no completed fuzzing/webapp/api jobs).
    mock_wm.start_worker.reset_mock()
    await _check_vulnscan_trigger()
    assert mock_wm.start_worker.call_count == 0

    # Chain trigger: should fire (recon completed, no chain run yet).
    mock_push.reset_mock()
    await _check_chain_trigger()
    chain_calls = [c for c in mock_push.call_args_list if c.args and c.args[0] == "chain_queue"]
    assert len(chain_calls) == 1
    assert chain_calls[0].args[1]["target_id"] == tid
    assert chain_calls[0].args[1]["trigger_phase"] == "recon"

    # Reporting trigger: should NOT fire (no completed chain job yet).
    mock_wm.start_worker.reset_mock()
    await _check_reporting_trigger()
    assert mock_wm.start_worker.call_count == 0

    # --- Phase 4: Mark fuzzing complete and verify vulnscan + reporting chain ---
    async with get_session() as session:
        session.add(JobState(
            target_id=tid,
            container_name=_container("fuzzing", tid),
            current_phase="fuzzing",
            status="COMPLETED",
            last_seen=_now(),
        ))
        await session.commit()

    # Now vulnscan should fire.
    mock_wm.start_worker.reset_mock()
    await _check_vulnscan_trigger()
    assert mock_wm.start_worker.call_count == 1
    assert mock_wm.start_worker.call_args.kwargs["image"] == WORKER_IMAGES["vulnscan"]

    # --- Phase 5: Mark chain complete and verify reporting ---
    async with get_session() as session:
        session.add(JobState(
            target_id=tid,
            container_name=_container("chain", tid),
            current_phase="chain",
            status="COMPLETED",
            last_seen=_now(),
        ))
        await session.commit()

    mock_wm.start_worker.reset_mock()
    await _check_reporting_trigger()
    assert mock_wm.start_worker.call_count == 1
    assert mock_wm.start_worker.call_args.kwargs["image"] == WORKER_IMAGES["reporting"]


# ---------------------------------------------------------------------------
# Negative / edge-case tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recon_trigger_skips_completed_target(seed_target, mock_wm, mock_push):
    """A target with a COMPLETED recon job should NOT re-trigger recon."""
    async with get_session() as session:
        job = JobState(
            target_id=seed_target,
            container_name=_container("recon", seed_target),
            current_phase="passive_discovery",
            status="COMPLETED",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_recon_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_cloud_trigger_skips_stale_assets(seed_target, mock_wm, mock_push):
    """CloudAsset created BEFORE the last completed cloud job should NOT trigger."""
    async with get_session() as session:
        # Create cloud asset first.
        ca = CloudAsset(
            target_id=seed_target,
            provider="gcp",
            asset_type="gcs_bucket",
            url="gs://stale-bucket",
        )
        session.add(ca)
        await session.commit()

        # Then mark a cloud job as completed AFTER the asset was created.
        job = JobState(
            target_id=seed_target,
            container_name=_container("cloud_testing", seed_target),
            current_phase="cloud_enum",
            status="COMPLETED",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_cloud_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_web_trigger_skips_closed_ports(seed_target, mock_wm, mock_push):
    """A closed port 443 should NOT trigger web workers."""
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target,
            asset_type="ip",
            asset_value="10.0.0.2",
            source_tool="nmap",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id,
            port=443,
            protocol="tcp",
            service="https",
            state="closed",
        )
        session.add(loc)
        await session.commit()

    await _check_web_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_api_trigger_skips_below_threshold(seed_target, mock_wm, mock_push):
    """Fewer than 20 parameters should NOT trigger api_testing."""
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target,
            asset_type="url",
            asset_value="https://testcorp.com/small",
            source_tool="katana",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        for i in range(10):
            session.add(Parameter(
                asset_id=asset.id,
                param_name=f"q{i}",
                param_value=f"v{i}",
                source_url=f"https://testcorp.com/small?q{i}=v{i}",
            ))
        await session.commit()

    await _check_api_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_network_trigger_skips_web_ports(seed_target, mock_wm, mock_push):
    """Open port 80 should NOT trigger the network worker (only web trigger handles those)."""
    async with get_session() as session:
        asset = Asset(
            target_id=seed_target,
            asset_type="ip",
            asset_value="10.0.0.7",
            source_tool="nmap",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id,
            port=80,
            protocol="tcp",
            service="http",
            state="open",
        )
        session.add(loc)
        await session.commit()

    await _check_network_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_vulnscan_trigger_does_not_fire_without_prereqs(seed_target, mock_wm, mock_push):
    """Vulnscan should NOT fire when there are no completed fuzzing/webapp/api jobs."""
    await _check_vulnscan_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_chain_trigger_ignores_non_chain_workers(seed_target, mock_wm, mock_push):
    """Completed network or mobile jobs should NOT trigger chain worker
    (only recon/cloud/fuzzing/webapp/api)."""
    async with get_session() as session:
        job = JobState(
            target_id=seed_target,
            container_name=_container("network", seed_target),
            current_phase="port_discovery",
            status="COMPLETED",
            last_seen=_now(),
        )
        session.add(job)
        await session.commit()

    await _check_chain_trigger()

    chain_calls = [c for c in mock_push.call_args_list if c.args and c.args[0] == "chain_queue"]
    assert len(chain_calls) == 0


@pytest.mark.asyncio
async def test_reporting_trigger_does_not_fire_without_chain(seed_target, mock_wm, mock_push):
    """Reporting should NOT fire if no chain job has completed."""
    await _check_reporting_trigger()
    mock_wm.start_worker.assert_not_called()


@pytest.mark.asyncio
async def test_worker_queued_when_resources_low(seed_target, mock_wm, mock_push):
    """When should_queue returns True, _trigger_worker queues instead of starting."""
    mock_wm.should_queue = AsyncMock(return_value=True)

    await _check_recon_trigger()

    # start_worker should NOT have been called.
    mock_wm.start_worker.assert_not_called()

    # But a JobState with status QUEUED should exist.
    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(JobState).where(
                JobState.target_id == seed_target,
                JobState.container_name == _container("recon", seed_target),
            )
        )
        job = result.scalar_one()
        assert job.status == "QUEUED"
