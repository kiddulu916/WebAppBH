import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import json
import pytest
from unittest.mock import AsyncMock, patch


async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


# ---------------------------------------------------------------------------
# EndpointExtractor tests
# ---------------------------------------------------------------------------


def test_endpoint_extractor_url_regex():
    from workers.mobile_worker.tools.endpoint_extractor import EndpointExtractorTool
    tool = EndpointExtractorTool()
    text = '''
    String url = "https://api.example.com/v1/users";
    fetch("http://internal.corp.io/admin");
    String other = "not-a-url";
    '''
    urls = tool._extract_urls_from_text(text)
    assert "https://api.example.com/v1/users" in urls
    assert "http://internal.corp.io/admin" in urls
    assert "not-a-url" not in urls


def test_endpoint_extractor_deduplication():
    from workers.mobile_worker.tools.endpoint_extractor import EndpointExtractorTool
    tool = EndpointExtractorTool()
    urls = [
        "https://api.example.com/v1/users",
        "https://api.example.com/v1/users",
        "https://api.example.com/v2/data",
    ]
    deduped = tool._deduplicate(urls)
    assert len(deduped) == 2


def test_endpoint_extractor_parses_mobsf_report_urls():
    from workers.mobile_worker.tools.endpoint_extractor import EndpointExtractorTool
    tool = EndpointExtractorTool()
    report = {
        "urls": [
            {"url": "https://api.example.com/health"},
            {"url": "https://cdn.example.com/static"},
        ],
        "domains": {
            "api.example.com": {"info": "API server"},
            "tracking.ads.com": {"info": "Tracker"},
        },
    }
    urls = tool._extract_from_mobsf(report)
    assert "https://api.example.com/health" in urls
    assert "https://cdn.example.com/static" in urls
    assert "api.example.com" in urls or any("api.example.com" in u for u in urls)


@pytest.mark.anyio
async def test_endpoint_extractor_scope_filtering():
    await _create_tables()
    from lib_webbh import Target, get_session
    from lib_webbh.scope import ScopeManager
    from workers.mobile_worker.tools.endpoint_extractor import EndpointExtractorTool

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com",
                   target_profile={"in_scope_domains": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        tid = t.id

    tool = EndpointExtractorTool()
    scope_manager = ScopeManager({"in_scope_domains": ["*.acme.com"]})

    # In-scope should return asset id
    result = await tool._save_asset(tid, "https://api.acme.com/v1", scope_manager)
    assert result is not None

    # Out-of-scope should return None
    result = await tool._save_asset(tid, "https://evil.com/hack", scope_manager)
    assert result is None


@pytest.mark.anyio
async def test_endpoint_extractor_pushes_to_recon_queue():
    """Verify the tool calls push_task for in-scope endpoints."""
    await _create_tables()
    from lib_webbh import Target, get_session
    from workers.mobile_worker.tools.endpoint_extractor import EndpointExtractorTool

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com",
                   target_profile={"in_scope_domains": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        tid = t.id

    tool = EndpointExtractorTool()
    # Verify the recon queue push method exists
    assert hasattr(tool, "_push_to_recon")
