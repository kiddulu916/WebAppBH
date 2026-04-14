import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Concurrency tests
# ---------------------------------------------------------------------------


def test_mobile_concurrency_defaults():
    from workers.mobile_worker.concurrency import WeightClass, get_semaphores
    static, dynamic = get_semaphores(force_new=True)
    assert static._value == 3
    assert dynamic._value == 1


def test_mobile_weight_class_enum():
    from workers.mobile_worker.concurrency import WeightClass
    assert WeightClass.STATIC.value == "static"
    assert WeightClass.DYNAMIC.value == "dynamic"


# ---------------------------------------------------------------------------
# Helper: create tables
# ---------------------------------------------------------------------------


async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _make_dummy_mobile_tool():
    from workers.mobile_worker.base_tool import MobileTestTool
    from workers.mobile_worker.concurrency import WeightClass

    class DummyMobileTool(MobileTestTool):
        name = "dummy-mobile"
        weight_class = WeightClass.STATIC

        async def execute(self, target, scope_manager, target_id, container_name,
                          **kwargs):
            return {"found": 0, "in_scope": 0, "new": 0}

    return DummyMobileTool()


# ---------------------------------------------------------------------------
# Base tool tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_base_tool_check_cooldown_no_job():
    await _create_tables()
    tool = _make_dummy_mobile_tool()
    result = await tool.check_cooldown(999, "test-mobile")
    assert result is False


@pytest.mark.anyio
async def test_base_tool_save_mobile_app_upsert():
    await _create_tables()
    from lib_webbh import Target, MobileApp, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.commit()
        tid = t.id

    tool = _make_dummy_mobile_tool()
    app_id = await tool._save_mobile_app(
        target_id=tid, platform="android",
        package_name="com.acme.app", version="1.0",
    )
    assert app_id > 0

    # Upsert: same (target_id, platform, package_name) should update, not duplicate
    app_id2 = await tool._save_mobile_app(
        target_id=tid, platform="android",
        package_name="com.acme.app", version="2.0",
    )
    assert app_id2 == app_id

    # Verify version was updated
    async with get_session() as session:
        from sqlalchemy import select
        row = (await session.execute(
            select(MobileApp).where(MobileApp.id == app_id)
        )).scalar_one()
        assert row.version == "2.0"


@pytest.mark.anyio
async def test_base_tool_get_binary_urls():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a1 = Asset(target_id=t.id, asset_type="url",
                   asset_value="https://cdn.acme.com/app.apk")
        a2 = Asset(target_id=t.id, asset_type="url",
                   asset_value="https://cdn.acme.com/release.ipa")
        a3 = Asset(target_id=t.id, asset_type="url",
                   asset_value="https://acme.com/about")
        session.add_all([a1, a2, a3])
        await session.commit()
        tid = t.id

    tool = _make_dummy_mobile_tool()
    urls = await tool._get_binary_urls(tid)
    values = [u[1] for u in urls]
    assert "https://cdn.acme.com/app.apk" in values
    assert "https://cdn.acme.com/release.ipa" in values
    assert "https://acme.com/about" not in values


@pytest.mark.anyio
async def test_base_tool_save_vulnerability():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a = Asset(target_id=t.id, asset_type="url",
                  asset_value="https://acme.com/api")
        session.add(a)
        await session.commit()
        tid, aid = t.id, a.id

    tool = _make_dummy_mobile_tool()
    with patch.object(tool, "_create_alert", new_callable=AsyncMock):
        vuln_id = await tool._save_vulnerability(
            target_id=tid, asset_id=aid, severity="high",
            title="Hardcoded AWS Key", description="Found AKIA...",
        )
    assert vuln_id > 0


@pytest.mark.anyio
async def test_base_tool_scan_drop_folder(tmp_path):
    await _create_tables()
    # Create fake drop folder
    target_dir = tmp_path / "1"
    target_dir.mkdir()
    (target_dir / "test.apk").write_bytes(b"fake")
    (target_dir / "test.ipa").write_bytes(b"fake")
    (target_dir / "readme.txt").write_bytes(b"ignore")

    tool = _make_dummy_mobile_tool()
    with patch("workers.mobile_worker.base_tool.MOBILE_BINARIES_DIR", str(tmp_path)):
        files = tool._scan_drop_folder(1)
    filenames = [os.path.basename(f) for f in files]
    assert "test.apk" in filenames
    assert "test.ipa" in filenames
    assert "readme.txt" not in filenames


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_pipeline_stages_defined():
    from workers.mobile_worker.pipeline import STAGES, STAGE_INDEX
    assert len(STAGES) == 5
    assert STAGES[0].name == "acquire_decompile"
    assert STAGES[1].name == "secret_extraction"
    assert STAGES[2].name == "configuration_audit"
    assert STAGES[3].name == "dynamic_analysis"
    assert STAGES[4].name == "endpoint_feedback"
    assert STAGE_INDEX["acquire_decompile"] == 0
    assert STAGE_INDEX["endpoint_feedback"] == 4


@pytest.mark.anyio
async def test_pipeline_resumes_from_checkpoint():
    await _create_tables()
    from lib_webbh import Target, JobState, get_session
    from workers.mobile_worker.pipeline import Pipeline
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        job = JobState(target_id=t.id, container_name="test-mobile",
                       current_phase="secret_extraction", last_completed_stage="secret_extraction",
                       status="COMPLETED")
        session.add(job)
        await session.commit()
        tid = t.id
    pipeline = Pipeline(target_id=tid, container_name="test-mobile")
    phase = await pipeline._get_resume_stage()
    assert phase == "secret_extraction"


@pytest.mark.anyio
async def test_pipeline_aggregate_results():
    from workers.mobile_worker.pipeline import Pipeline
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
    from workers.mobile_worker.main import handle_message
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com",
                   target_profile={"scope": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        tid = t.id
    with (
        patch("workers.mobile_worker.main.Pipeline") as MockPipeline,
        patch("workers.mobile_worker.main.get_container_name", return_value="test-mobile"),
    ):
        mock_pipeline = MagicMock()
        mock_pipeline.run = AsyncMock()
        MockPipeline.return_value = mock_pipeline
        await handle_message("msg-1", {"target_id": tid})
    async with get_session() as session:
        from sqlalchemy import select
        stmt = select(JobState).where(
            JobState.target_id == tid,
            JobState.container_name == "test-mobile",
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        assert job is not None


@pytest.mark.anyio
async def test_main_handle_message_skips_missing_target():
    await _create_tables()
    from workers.mobile_worker.main import handle_message
    # Should not crash on missing target
    await handle_message("msg-2", {"target_id": 99999})


# ---------------------------------------------------------------------------
# Final integration tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_pipeline_all_tools_wired():
    """Verify all 12 tools are registered in their correct stages."""
    from workers.mobile_worker.pipeline import STAGES

    stage_names = {s.name: [cls.name for cls in s.tool_classes] for s in STAGES}

    # Stage 1: acquire_decompile
    assert "binary_downloader" in stage_names["acquire_decompile"]
    assert "apktool_decompiler" in stage_names["acquire_decompile"]
    assert "mobsf_scanner" in stage_names["acquire_decompile"]

    # Stage 2: secret_extraction
    assert "secret_scanner" in stage_names["secret_extraction"]
    assert "mobsf_secrets" in stage_names["secret_extraction"]

    # Stage 3: configuration_audit
    assert "manifest_auditor" in stage_names["configuration_audit"]
    assert "ios_plist_auditor" in stage_names["configuration_audit"]
    assert "deeplink_analyzer" in stage_names["configuration_audit"]

    # Stage 4: dynamic_analysis
    assert "frida_crypto_hooker" in stage_names["dynamic_analysis"]
    assert "frida_root_detector" in stage_names["dynamic_analysis"]
    assert "frida_component_prober" in stage_names["dynamic_analysis"]

    # Stage 5: endpoint_feedback
    assert "endpoint_extractor" in stage_names["endpoint_feedback"]


@pytest.mark.anyio
async def test_pipeline_tool_count():
    from workers.mobile_worker.pipeline import STAGES
    total = sum(len(s.tool_classes) for s in STAGES)
    assert total == 12


@pytest.mark.anyio
async def test_all_tools_importable():
    from workers.mobile_worker.tools import (
        BinaryDownloaderTool, ApktoolDecompilerTool, MobsfScannerTool,
        SecretScannerTool, MobsfSecretsTool,
        ManifestAuditorTool, IosPlistAuditorTool, DeeplinkAnalyzerTool,
        FridaCryptoHookerTool, FridaRootDetectorTool, FridaComponentProberTool,
        EndpointExtractorTool,
    )
    tools = [
        BinaryDownloaderTool, ApktoolDecompilerTool, MobsfScannerTool,
        SecretScannerTool, MobsfSecretsTool,
        ManifestAuditorTool, IosPlistAuditorTool, DeeplinkAnalyzerTool,
        FridaCryptoHookerTool, FridaRootDetectorTool, FridaComponentProberTool,
        EndpointExtractorTool,
    ]
    for tool_cls in tools:
        t = tool_cls()
        assert hasattr(t, "name")
        assert hasattr(t, "weight_class")
        assert hasattr(t, "execute")
