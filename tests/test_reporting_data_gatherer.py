# tests/test_reporting_data_gatherer.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
from lib_webbh.database import (
    Asset, Base, CloudAsset, Location, Observation, Target, Vulnerability,
    get_engine, get_session,
)
from workers.reporting_worker.data_gatherer import gather_report_data


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
async def seed_data(db):
    async with get_session() as session:
        t = Target(company_name="AcmeCorp", base_domain="acme.com", target_profile={"in_scope_domains": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.acme.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        loc = Location(asset_id=a.id, port=443, protocol="https", service="http", state="open")
        session.add(loc)

        obs = Observation(asset_id=a.id, tech_stack={"framework": "React"}, status_code=200)
        session.add(obs)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="Reflected XSS", description="XSS in search param",
            poc="GET /search?q=<script>alert(1)</script>", source_tool="nuclei",
        )
        session.add(v)

        ca = CloudAsset(target_id=t.id, provider="aws", asset_type="s3", url="https://acme-backup.s3.amazonaws.com", is_public=True)
        session.add(ca)

        await session.commit()
        return t.id


@pytest.mark.anyio
async def test_gather_returns_report_context(seed_data):
    ctx = await gather_report_data(seed_data, screenshot_base="/nonexistent")
    assert ctx.target_id == seed_data
    assert ctx.company_name == "AcmeCorp"
    assert ctx.base_domain == "acme.com"
    assert len(ctx.vulnerabilities) == 1
    assert len(ctx.assets) == 1
    assert len(ctx.cloud_assets) == 1


@pytest.mark.anyio
async def test_gather_empty_target(db):
    async with get_session() as session:
        t = Target(company_name="EmptyCorp", base_domain="empty.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        tid = t.id
    ctx = await gather_report_data(tid, screenshot_base="/nonexistent")
    assert ctx.vulnerabilities == []
    assert ctx.assets == []
