"""Integration: run webapp pipeline with mocked tools, verify completion."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"

from lib_webbh import Asset, Base, JobState, Location, Target, get_engine, get_session
from sqlalchemy import select


@pytest.fixture
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def seed_target(setup_db):
    """Seed a target with a domain asset and open port 80 location."""
    async with get_session() as session:
        target = Target(
            company_name="TestCorp",
            base_domain="example.com",
            target_profile={
                "in_scope_domains": ["*.example.com"],
                "out_scope_domains": [],
                "in_scope_cidrs": [],
                "in_scope_regex": [],
            },
        )
        session.add(target)
        await session.flush()
        target_id = target.id

        asset = Asset(
            target_id=target_id,
            asset_type="domain",
            asset_value="www.example.com",
            source_tool="seed",
        )
        session.add(asset)
        await session.flush()
        asset_id = asset.id

        location = Location(
            asset_id=asset_id,
            port=80,
            protocol="http",
            state="open",
        )
        session.add(location)

        job = JobState(
            target_id=target_id,
            container_name="webapp-worker",
            current_phase="init",
            status="RUNNING",
        )
        session.add(job)
        await session.commit()
        return target_id


@pytest.mark.anyio
async def test_webapp_pipeline_full_flow(seed_target):
    """Pipeline should run all 6 stages and mark job COMPLETED."""
    target_id = seed_target

    async with get_session() as session:
        result = await session.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one()

    from lib_webbh.scope import ScopeManager
    from workers.webapp_worker.pipeline import Pipeline

    scope_mgr = ScopeManager(target.target_profile)
    pipeline = Pipeline(target_id=target_id, container_name="webapp-worker")

    # Mock BrowserManager
    mock_browser_mgr = MagicMock()
    mock_page = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.on = MagicMock()
    mock_page.evaluate = AsyncMock(return_value=[])
    mock_page.add_init_script = AsyncMock()
    mock_page.close = AsyncMock()
    mock_page.set_extra_http_headers = AsyncMock()
    mock_page.set_default_timeout = MagicMock()
    mock_browser_mgr.new_page = AsyncMock(return_value=mock_page)
    mock_browser_mgr.release_page = AsyncMock()
    mock_browser_mgr.start = AsyncMock()
    mock_browser_mgr.shutdown = AsyncMock()

    # Mock subprocess for CLI tools (linkfinder, jsminer, mantra, secretfinder, newman)
    async def mock_subprocess(*cmd, **kwargs):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        return mock_proc

    # Mock httpx for HTTP tools
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html><body>Hello</body></html>"
    mock_response.headers = MagicMock()
    mock_response.headers.items = MagicMock(return_value=[
        ("Content-Type", "text/html"),
    ])
    mock_response.headers.multi_items = MagicMock(return_value=[
        ("content-type", "text/html"),
    ])
    mock_response.headers.get = MagicMock(return_value="")
    mock_response.headers.__contains__ = MagicMock(return_value=False)
    mock_response.headers.__getitem__ = MagicMock(return_value="")

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.aclose = AsyncMock()

    with (
        patch(
            "workers.webapp_worker.pipeline.BrowserManager",
            return_value=mock_browser_mgr,
        ),
        patch(
            "workers.webapp_worker.pipeline.push_task",
            new_callable=AsyncMock,
        ) as mock_push,
        patch(
            "asyncio.create_subprocess_exec",
            side_effect=mock_subprocess,
        ),
        patch(
            "workers.webapp_worker.pipeline.Pipeline._get_http_client",
            return_value=mock_client,
        ),
    ):
        await pipeline.run(target, scope_mgr)

    # Verify job is marked COMPLETED
    async with get_session() as session:
        result = await session.execute(
            select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == "webapp-worker",
            )
        )
        job = result.scalar_one()
        assert job.status == "COMPLETED"

    # Verify pipeline_complete event was pushed
    push_calls = [c for c in mock_push.call_args_list if "PIPELINE_COMPLETE" in str(c)]
    assert len(push_calls) >= 1
