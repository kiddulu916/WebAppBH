import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def test_concurrency_semaphore_defaults():
    from workers.api_worker.concurrency import WeightClass, get_semaphores
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 2
    assert light._value >= 1


def test_weight_class_enum():
    from workers.api_worker.concurrency import WeightClass
    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


# ---------------------------------------------------------------------------
# ApiTestTool base class tests
# ---------------------------------------------------------------------------


async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _make_dummy_tool():
    from workers.api_worker.base_tool import ApiTestTool
    from workers.api_worker.concurrency import WeightClass

    class DummyApiTool(ApiTestTool):
        name = "dummy-api"
        weight_class = WeightClass.LIGHT

        async def execute(self, target, scope_manager, target_id, container_name,
                          headers=None, **kwargs):
            return {"found": 0, "in_scope": 0, "new": 0}

    return DummyApiTool()


@pytest.mark.anyio
async def test_api_base_tool_check_cooldown_no_job():
    await _create_tables()
    tool = _make_dummy_tool()
    result = await tool.check_cooldown(999, "test-container")
    assert result is False


@pytest.mark.anyio
async def test_api_base_tool_save_vulnerability():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/api")
        session.add(a)
        await session.commit()
        tid, aid = t.id, a.id
    tool = _make_dummy_tool()
    with patch.object(tool, "_create_alert", new_callable=AsyncMock):
        vuln_id = await tool._save_vulnerability(
            target_id=tid, asset_id=aid, severity="high",
            title="Test JWT bypass", description="Algorithm confusion", poc="eyJ...",
        )
    assert vuln_id > 0


@pytest.mark.anyio
async def test_api_base_tool_save_api_schema():
    await _create_tables()
    from lib_webbh import Target, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.commit()
        tid = t.id
    tool = _make_dummy_tool()
    schema_id = await tool._save_api_schema(
        target_id=tid, asset_id=None, method="GET",
        path="/api/v1/users", params={"query": ["id"]},
        content_type="application/json", source_tool="ffuf_api", spec_type="discovered",
    )
    assert schema_id > 0
    # Upsert — same method+path should return same id
    schema_id2 = await tool._save_api_schema(
        target_id=tid, asset_id=None, method="GET",
        path="/api/v1/users", params={"query": ["id", "page"]},
        content_type="application/json", source_tool="openapi_parser", spec_type="openapi",
    )
    assert schema_id2 == schema_id


@pytest.mark.anyio
async def test_api_base_tool_get_api_urls():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a1 = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/api/v1/users")
        a2 = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/about")
        a3 = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/graphql")
        session.add_all([a1, a2, a3])
        await session.commit()
        tid = t.id
    tool = _make_dummy_tool()
    api_urls = await tool._get_api_urls(tid)
    values = [u[1] for u in api_urls]
    assert "https://acme.com/api/v1/users" in values
    assert "https://acme.com/graphql" in values
    assert "https://acme.com/about" not in values


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_pipeline_stages_defined():
    from workers.api_worker.pipeline import STAGES, STAGE_INDEX
    assert len(STAGES) == 4
    assert STAGES[0].name == "api_discovery"
    assert STAGES[1].name == "auth_testing"
    assert STAGES[2].name == "injection_testing"
    assert STAGES[3].name == "abuse_testing"
    assert STAGE_INDEX["api_discovery"] == 0


@pytest.mark.anyio
async def test_pipeline_resumes_from_checkpoint():
    await _create_tables()
    from lib_webbh import Target, JobState, get_session
    from workers.api_worker.pipeline import Pipeline
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        job = JobState(target_id=t.id, container_name="test-api",
                       current_phase="api_discovery", last_completed_stage="api_discovery",
                       status="COMPLETED")
        session.add(job)
        await session.commit()
        tid = t.id
    pipeline = Pipeline(target_id=tid, container_name="test-api")
    phase = await pipeline._get_resume_stage()
    assert phase == "api_discovery"


@pytest.mark.anyio
async def test_pipeline_aggregate_results():
    from workers.api_worker.pipeline import Pipeline
    p = Pipeline(target_id=1, container_name="test")
    results = [
        {"found": 5, "in_scope": 3, "new": 2},
        {"found": 10, "in_scope": 8, "new": 6},
        ValueError("tool failed"),
    ]
    agg = p._aggregate_results("test_stage", results)
    assert agg["found"] == 15
    assert agg["in_scope"] == 11
    assert agg["new"] == 8


# ---------------------------------------------------------------------------
# main.py tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_main_handle_message_creates_job_state():
    await _create_tables()
    from lib_webbh import Target, JobState, get_session
    from workers.api_worker.main import handle_message
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com",
                   target_profile={"scope": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        tid = t.id
    with (
        patch("workers.api_worker.main.Pipeline") as MockPipeline,
        patch("workers.api_worker.main.get_container_name", return_value="test-api"),
    ):
        mock_pipeline = MagicMock()
        mock_pipeline.run = AsyncMock()
        MockPipeline.return_value = mock_pipeline
        await handle_message("msg-1", {"target_id": tid})
    async with get_session() as session:
        from sqlalchemy import select
        stmt = select(JobState).where(JobState.target_id == tid, JobState.container_name == "test-api")
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        assert job is not None


@pytest.mark.anyio
async def test_main_handle_message_skips_missing_target():
    await _create_tables()
    from workers.api_worker.main import handle_message
    await handle_message("msg-2", {"target_id": 99999})


# ---------------------------------------------------------------------------
# Final integration tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_pipeline_all_tools_wired():
    """Verify all 12 tools are registered in their correct stages."""
    from workers.api_worker.pipeline import STAGES

    stage_names = {s.name: [cls.name for cls in s.tool_classes] for s in STAGES}

    # Stage 1: api_discovery
    assert "ffuf_api" in stage_names["api_discovery"]
    assert "openapi_parser" in stage_names["api_discovery"]
    assert "graphql_introspect" in stage_names["api_discovery"]
    assert "trufflehog" in stage_names["api_discovery"]

    # Stage 2: auth_testing
    assert "jwt_tool" in stage_names["auth_testing"]
    assert "oauth_tester" in stage_names["auth_testing"]
    assert "cors_scanner" in stage_names["auth_testing"]

    # Stage 3: injection_testing
    assert "idor_tester" in stage_names["injection_testing"]
    assert "mass_assign_tester" in stage_names["injection_testing"]
    assert "nosqlmap" in stage_names["injection_testing"]

    # Stage 4: abuse_testing
    assert "rate_limit_tester" in stage_names["abuse_testing"]
    assert "graphql_cop" in stage_names["abuse_testing"]


@pytest.mark.anyio
async def test_pipeline_tool_count():
    from workers.api_worker.pipeline import STAGES
    total = sum(len(s.tool_classes) for s in STAGES)
    assert total == 12


@pytest.mark.anyio
async def test_all_tools_importable():
    from workers.api_worker.tools import (
        FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool,
        JwtTool, OauthTesterTool, CorsScannerTool,
        IdorTesterTool, MassAssignTesterTool, NosqlmapTool,
        RateLimitTesterTool, GraphqlCopTool,
    )
    tools = [
        FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool,
        JwtTool, OauthTesterTool, CorsScannerTool,
        IdorTesterTool, MassAssignTesterTool, NosqlmapTool,
        RateLimitTesterTool, GraphqlCopTool,
    ]
    for tool_cls in tools:
        t = tool_cls()
        assert hasattr(t, "name")
        assert hasattr(t, "weight_class")
        assert hasattr(t, "execute")
