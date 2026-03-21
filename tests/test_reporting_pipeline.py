# tests/test_reporting_pipeline.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from lib_webbh.database import (
    Asset, Base, Location, Target, Vulnerability, get_engine, get_session,
)
from workers.reporting_worker.pipeline import Pipeline, STAGES


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_pipeline_has_four_stages():
    assert len(STAGES) == 4


def test_stage_names():
    names = [s.name for s in STAGES]
    assert names == ["data_gathering", "deduplication", "rendering", "export"]


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target_with_vuln(db):
    async with get_session() as session:
        t = Target(company_name="TestCorp", base_domain="test.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.test.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        loc = Location(asset_id=a.id, port=443, protocol="https", service="http", state="open")
        session.add(loc)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="XSS", description="Reflected XSS",
            poc="GET /search?q=<script>", source_tool="nuclei",
        )
        session.add(v)
        await session.commit()
        return t.id


@pytest.mark.anyio
async def test_pipeline_run_markdown_only(seed_target_with_vuln):
    pipeline = Pipeline()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
            result = await pipeline.run(
                target_id=seed_target_with_vuln,
                formats=["hackerone_md"],
                platform="hackerone",
                container_name="test-reporting",
                output_base=tmpdir,
            )
        assert len(result) >= 1
        assert any(f.endswith(".md") for f in result)
