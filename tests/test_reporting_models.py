# tests/test_reporting_models.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
from lib_webbh.database import Base, Target, Vulnerability, get_engine, get_session


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
        t = Target(company_name="TestCorp", base_domain="testcorp.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.mark.anyio
async def test_vulnerability_has_cvss_score_column(seed_target):
    async with get_session() as session:
        v = Vulnerability(
            target_id=seed_target, severity="high", title="Test XSS",
            cvss_score=7.5,
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        assert v.cvss_score == 7.5


@pytest.mark.anyio
async def test_vulnerability_has_remediation_column(seed_target):
    async with get_session() as session:
        v = Vulnerability(
            target_id=seed_target, severity="medium", title="Test SQLi",
            remediation="Use parameterized queries.",
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        assert v.remediation == "Use parameterized queries."


@pytest.mark.anyio
async def test_vulnerability_new_columns_nullable(seed_target):
    async with get_session() as session:
        v = Vulnerability(
            target_id=seed_target, severity="low", title="Info Disclosure",
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        assert v.cvss_score is None
        assert v.remediation is None
