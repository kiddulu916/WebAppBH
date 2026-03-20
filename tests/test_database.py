import os
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from lib_webbh.database import get_engine, get_session, Base


def test_get_engine_returns_async_engine():
    engine = get_engine()
    assert isinstance(engine, AsyncEngine)


def test_get_engine_is_singleton():
    e1 = get_engine()
    e2 = get_engine()
    assert e1 is e2


@pytest.mark.asyncio
async def test_get_session_returns_async_session():
    async with get_session() as session:
        assert isinstance(session, AsyncSession)


@pytest.mark.asyncio
async def test_create_all_tables():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


from lib_webbh.database import (
    Target, Asset, Identity, Location, Observation,
    CloudAsset, Parameter, Vulnerability, JobState, Alert,
)


@pytest.mark.asyncio
async def test_insert_target_and_asset():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with get_session() as session:
        target = Target(company_name="TestCorp", base_domain="testcorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)
        asset = Asset(target_id=target.id, asset_type="subdomain", asset_value="api.testcorp.com", source_tool="amass")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        assert target.id is not None
        assert asset.target_id == target.id
        assert asset.asset_value == "api.testcorp.com"


@pytest.mark.asyncio
async def test_insert_location_linked_to_asset():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with get_session() as session:
        target = Target(company_name="LocCorp", base_domain="loccorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)
        asset = Asset(target_id=target.id, asset_type="ip", asset_value="10.0.0.1", source_tool="nmap")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        loc = Location(asset_id=asset.id, port=443, protocol="tcp", service="https", state="open")
        session.add(loc)
        await session.commit()
        await session.refresh(loc)
        assert loc.asset_id == asset.id
        assert loc.port == 443


@pytest.mark.asyncio
async def test_insert_vulnerability_with_severity():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with get_session() as session:
        target = Target(company_name="VulnCorp", base_domain="vulncorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)
        asset = Asset(target_id=target.id, asset_type="subdomain", asset_value="admin.vulncorp.com", source_tool="subfinder")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        vuln = Vulnerability(target_id=target.id, asset_id=asset.id, severity="critical", title="SQL Injection", description="Login form injectable", poc="sqlmap -u '...'", source_tool="sqlmap")
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)
        assert vuln.severity == "critical"
        assert vuln.target_id == target.id


@pytest.mark.asyncio
async def test_job_state_status_values():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with get_session() as session:
        target = Target(company_name="JobCorp", base_domain="jobcorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)
        job = JobState(target_id=target.id, container_name="recon-core-01", current_phase="recon", status="RUNNING", last_tool_executed="amass")
        session.add(job)
        await session.commit()
        await session.refresh(job)
        assert job.status == "RUNNING"
        assert job.container_name == "recon-core-01"


def test_api_schema_model_importable():
    from lib_webbh import ApiSchema
    assert ApiSchema.__tablename__ == "api_schemas"


@pytest.mark.asyncio
async def test_api_schema_crud():
    from lib_webbh import ApiSchema

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()

        schema_row = ApiSchema(
            target_id=t.id,
            method="GET",
            path="/api/v1/users",
            params={"query": ["id", "page"]},
            auth_required=True,
            content_type="application/json",
            source_tool="openapi_parser",
            spec_type="openapi",
        )
        session.add(schema_row)
        await session.commit()

        from sqlalchemy import select
        stmt = select(ApiSchema).where(ApiSchema.target_id == t.id)
        result = await session.execute(stmt)
        row = result.scalar_one()
        assert row.method == "GET"
        assert row.path == "/api/v1/users"
        assert row.params == {"query": ["id", "page"]}
        assert row.auth_required is True
        assert row.spec_type == "openapi"


# ---------------------------------------------------------------------------
# MobileApp model tests
# ---------------------------------------------------------------------------


def test_mobile_app_model_importable():
    from lib_webbh import MobileApp
    assert MobileApp.__tablename__ == "mobile_apps"


@pytest.mark.asyncio
async def test_mobile_app_crud():
    from lib_webbh import MobileApp

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        t = Target(company_name="MobileCorp", base_domain="mobilecorp.com")
        session.add(t)
        await session.flush()

        app = MobileApp(
            target_id=t.id,
            platform="android",
            package_name="com.mobilecorp.app",
            version="1.2.3",
            permissions=["android.permission.INTERNET", "android.permission.CAMERA"],
            signing_info={"cn": "MobileCorp Inc"},
            mobsf_score=72.5,
            decompiled_path="/app/shared/mobile_analysis/1/com.mobilecorp.app",
            source_url="https://example.com/app.apk",
            source_tool="binary_downloader",
        )
        session.add(app)
        await session.commit()

        from sqlalchemy import select
        stmt = select(MobileApp).where(MobileApp.target_id == t.id)
        result = await session.execute(stmt)
        row = result.scalar_one()
        assert row.platform == "android"
        assert row.package_name == "com.mobilecorp.app"
        assert row.version == "1.2.3"
        assert row.mobsf_score == 72.5
        assert row.source_tool == "binary_downloader"


@pytest.mark.asyncio
async def test_mobile_app_unique_constraint():
    from lib_webbh import MobileApp
    from sqlalchemy.exc import IntegrityError

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        t = Target(company_name="DupCorp", base_domain="dupcorp.com")
        session.add(t)
        await session.flush()

        app1 = MobileApp(
            target_id=t.id, platform="android",
            package_name="com.dupcorp.app", source_tool="test",
        )
        session.add(app1)
        await session.commit()

    with pytest.raises(IntegrityError):
        async with get_session() as session:
            from sqlalchemy import select
            t_row = (await session.execute(
                select(Target).where(Target.base_domain == "dupcorp.com")
            )).scalar_one()
            app2 = MobileApp(
                target_id=t_row.id, platform="android",
                package_name="com.dupcorp.app", source_tool="test",
            )
            session.add(app2)
            await session.commit()
