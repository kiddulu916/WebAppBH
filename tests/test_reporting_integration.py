# tests/test_reporting_integration.py
"""End-to-end integration test for the reporting pipeline."""
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from lib_webbh.database import (
    Asset, Base, CloudAsset, Location, Observation, Target, Vulnerability,
    get_engine, get_session,
)
from workers.reporting_worker.pipeline import Pipeline


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
async def rich_target(db):
    """Seed a target with multiple vulns, assets, cloud assets, etc."""
    async with get_session() as session:
        t = Target(company_name="IntegCorp", base_domain="integ.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a1 = Asset(target_id=t.id, asset_type="domain", asset_value="app.integ.com", source_tool="subfinder")
        a2 = Asset(target_id=t.id, asset_type="domain", asset_value="api.integ.com", source_tool="amass")
        session.add_all([a1, a2])
        await session.commit()
        await session.refresh(a1)
        await session.refresh(a2)

        session.add_all([
            Location(asset_id=a1.id, port=443, protocol="https", service="http", state="open"),
            Location(asset_id=a2.id, port=443, protocol="https", service="http", state="open"),
            Observation(asset_id=a1.id, tech_stack={"framework": "React"}, status_code=200),
        ])

        session.add_all([
            Vulnerability(target_id=t.id, asset_id=a1.id, severity="critical", title="SQL Injection",
                          description="SQLi in search", poc="GET /search?q=1' OR 1=1--", source_tool="nuclei"),
            Vulnerability(target_id=t.id, asset_id=a2.id, severity="critical", title="SQL Injection",
                          description="SQLi in API", poc="POST /api/query", source_tool="nuclei"),
            Vulnerability(target_id=t.id, asset_id=a1.id, severity="high", title="Reflected XSS",
                          description="XSS in param", poc="GET /page?x=<script>", source_tool="nuclei"),
            Vulnerability(target_id=t.id, asset_id=a1.id, severity="low", title="Missing HSTS",
                          description="No HSTS header", poc=None, source_tool="nuclei"),
        ])

        session.add(CloudAsset(target_id=t.id, provider="aws", asset_type="s3",
                                url="https://integ-backup.s3.amazonaws.com", is_public=True))
        await session.commit()
        return t.id


@pytest.mark.anyio
async def test_full_pipeline_markdown(rich_target):
    pipeline = Pipeline()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
            paths = await pipeline.run(
                target_id=rich_target,
                formats=["hackerone_md"],
                platform="hackerone",
                container_name="test-reporting-integ",
                output_base=tmpdir,
            )
        assert len(paths) == 1
        assert paths[0].endswith(".md")
        content = open(paths[0]).read()
        assert "SQL Injection" in content
        assert "Reflected XSS" in content
        assert "Missing HSTS" in content


@pytest.mark.anyio
async def test_dedup_groups_same_vuln(rich_target):
    """Two SQLi vulns on different assets should be one finding group."""
    from workers.reporting_worker.data_gatherer import gather_report_data
    from workers.reporting_worker.deduplicator import deduplicate_and_enrich

    ctx = await gather_report_data(rich_target, screenshot_base="/nonexistent")
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])

    sqli_groups = [g for g in data.finding_groups if g.title == "SQL Injection"]
    assert len(sqli_groups) == 1
    assert len(sqli_groups[0].affected_assets) == 2


@pytest.mark.anyio
async def test_full_pipeline_multiple_formats(rich_target):
    """Test generating both markdown and PDF (PDF skipped if WeasyPrint not available)."""
    pipeline = Pipeline()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
            try:
                paths = await pipeline.run(
                    target_id=rich_target,
                    formats=["hackerone_md", "executive_pdf", "technical_pdf"],
                    platform="hackerone",
                    container_name="test-reporting-multi",
                    output_base=tmpdir,
                )
                assert any(p.endswith(".md") for p in paths)
                assert any(p.endswith(".pdf") for p in paths)
            except ImportError:
                pytest.skip("WeasyPrint not installed")
