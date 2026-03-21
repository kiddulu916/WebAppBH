# tests/test_reporting_main.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from lib_webbh.database import Base, Target, JobState, get_engine, get_session
from workers.reporting_worker.main import handle_message


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(company_name="TestCorp", base_domain="test.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.mark.anyio
async def test_handle_message_creates_job_state(seed_target):
    with patch("workers.reporting_worker.main.Pipeline") as MockPipeline:
        mock_pipeline = MockPipeline.return_value
        mock_pipeline.run = AsyncMock(return_value=["/tmp/report.md"])

        with patch("workers.reporting_worker.main.push_task", new_callable=AsyncMock):
            await handle_message("msg-1", {
                "target_id": seed_target,
                "formats": ["hackerone_md"],
                "platform": "hackerone",
            })

        async with get_session() as session:
            from sqlalchemy import select
            jobs = (await session.execute(select(JobState))).scalars().all()
            assert len(jobs) == 1
            assert jobs[0].target_id == seed_target


@pytest.mark.anyio
async def test_handle_message_nonexistent_target(db):
    with patch("workers.reporting_worker.main.Pipeline") as MockPipeline:
        with patch("workers.reporting_worker.main.push_task", new_callable=AsyncMock):
            await handle_message("msg-2", {
                "target_id": 9999,
                "formats": ["hackerone_md"],
                "platform": "hackerone",
            })
        MockPipeline.return_value.run.assert_not_called()
