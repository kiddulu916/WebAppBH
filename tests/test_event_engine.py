# tests/test_event_engine.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


async def test_evaluate_target_dispatches_ready_worker(db_session):
    from orchestrator.event_engine import EventEngine
    from orchestrator.resource_guard import ResourceGuard
    from lib_webbh.database import Target, JobState

    target = Target(company_name="Test", base_domain="target.com", priority=100)
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # Simulate info_gathering complete
    job = JobState(
        target_id=target.id,
        container_name="info_gathering",
        status="complete",
    )
    db_session.add(job)
    await db_session.commit()

    guard = ResourceGuard()
    engine = EventEngine(guard)

    with patch.object(engine, "_dispatch_worker", new_callable=AsyncMock) as mock_dispatch:
        await engine._evaluate_target(target, "green")
        # config_mgmt should be dispatched (its only dep is info_gathering which is complete)
        dispatched_workers = [call.args[1] for call in mock_dispatch.call_args_list]
        assert "config_mgmt" in dispatched_workers


async def test_evaluate_target_skips_pending_deps(db_session):
    from orchestrator.event_engine import EventEngine
    from orchestrator.resource_guard import ResourceGuard
    from lib_webbh.database import Target

    target = Target(company_name="Test", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # No jobs at all — info_gathering not complete
    guard = ResourceGuard()
    engine = EventEngine(guard)

    with patch.object(engine, "_dispatch_worker", new_callable=AsyncMock) as mock_dispatch:
        await engine._evaluate_target(target, "green")
        # Only info_gathering should be dispatched (no deps)
        dispatched_workers = [call.args[1] for call in mock_dispatch.call_args_list]
        assert "info_gathering" in dispatched_workers
        assert "config_mgmt" not in dispatched_workers
