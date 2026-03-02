"""
Integration test: Target -> Asset -> Location -> Observation -> Vulnerability -> Alert
+ ScopeManager check + Logger output
"""
import json
import os
import tempfile

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import lib_webbh.database as _db_mod  # noqa: E402

# Reset the engine/session singletons so this test gets a fresh in-memory DB
_db_mod._engine = None
_db_mod._session_factory = None

from lib_webbh import (  # noqa: E402
    get_engine,
    get_session,
    Base,
    Target,
    Asset,
    Location,
    Observation,
    Vulnerability,
    Alert,
    ScopeManager,
    setup_logger,
)


@pytest.mark.asyncio
async def test_full_recon_flow(capsys):
    # 1. Create tables
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Insert a target with scope profile
    async with get_session() as session:
        target = Target(
            company_name="IntegrationCorp",
            base_domain="integcorp.com",
            target_profile={
                "in_scope_domains": ["*.integcorp.com"],
                "out_scope_domains": ["admin.integcorp.com"],
                "in_scope_cidrs": ["10.0.0.0/24"],
                "in_scope_regex": [],
            },
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)

    # 3. ScopeManager checks
    scope = ScopeManager(target.target_profile)

    result_in = scope.is_in_scope("https://api.integcorp.com/v1/health")
    assert result_in.in_scope is True
    assert result_in.normalized == "api.integcorp.com"
    assert result_in.path == "/v1/health"

    result_out = scope.is_in_scope("admin.integcorp.com")
    assert result_out.in_scope is False

    result_ip = scope.is_in_scope("10.0.0.50")
    assert result_ip.in_scope is True
    assert result_ip.asset_type == "ip"

    # 4. Insert asset chain: asset -> location -> observation
    async with get_session() as session:
        asset = Asset(
            target_id=target.id,
            asset_type="subdomain",
            asset_value="api.integcorp.com",
            source_tool="amass",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id, port=443, protocol="tcp", service="https", state="open"
        )
        obs = Observation(
            asset_id=asset.id,
            tech_stack={"server": "nginx", "framework": "FastAPI"},
            page_title="API Docs",
            status_code=200,
            headers={"x-powered-by": "FastAPI"},
        )
        session.add_all([loc, obs])
        await session.commit()

        # 5. Insert vulnerability and alert
        vuln = Vulnerability(
            target_id=target.id,
            asset_id=asset.id,
            severity="high",
            title="IDOR on /v1/users",
            description="User ID enumeration via sequential IDs",
            poc="curl https://api.integcorp.com/v1/users/2",
            source_tool="manual",
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)

        alert = Alert(
            target_id=target.id,
            vulnerability_id=vuln.id,
            alert_type="high_severity_finding",
            message="IDOR found on api.integcorp.com",
            is_read=False,
        )
        session.add(alert)
        await session.commit()

    # 6. Logger output
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("integration-test", log_dir=tmpdir)
        bound = log.bind(target_id=target.id, asset_type="vulnerability")
        bound.info(
            "IDOR detected",
            extra={"asset": "api.integcorp.com", "source_tool": "manual"},
        )

        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["target_id"] == target.id
        assert record["extra"]["asset_type"] == "vulnerability"
        assert record["extra"]["asset"] == "api.integcorp.com"
