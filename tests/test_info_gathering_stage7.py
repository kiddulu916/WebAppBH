"""Unit tests for Stage 7 — Map Execution Paths (WSTG-INFO-07)."""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.url_classifier import classify_url


# ---------------------------------------------------------------------------
# url_classifier additions
# ---------------------------------------------------------------------------

def test_url_classifier_ws_prefix_returns_websocket():
    assert classify_url("ws://example.com/socket") == "websocket"


def test_url_classifier_wss_prefix_returns_websocket():
    assert classify_url("wss://example.com/ws") == "websocket"


def test_url_classifier_api_v1_path_returns_api_endpoint():
    assert classify_url("https://example.com/api/v1/users") == "api_endpoint"


def test_url_classifier_graphql_returns_api_endpoint():
    assert classify_url("https://example.com/graphql") == "api_endpoint"


def test_url_classifier_rest_path_returns_api_endpoint():
    assert classify_url("https://example.com/rest/items") == "api_endpoint"


def test_url_classifier_ws_check_runs_before_path_rules():
    # A ws:// URL with /api/ in the path should still be websocket, not api_endpoint
    assert classify_url("wss://example.com/api/ws") == "websocket"


# ---------------------------------------------------------------------------
# FormMapper URL cap removal
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_form_mapper_processes_more_than_20_urls():
    """FormMapper must not silently cap at 20 URLs."""
    from workers.info_gathering.tools.form_mapper import FormMapper

    tool = FormMapper()

    # 25 pre-existing URL assets in the DB mock (url, asset_id) pairs
    url_assets = [(f"https://example.com/page{i}", i + 1) for i in range(25)]

    fetched_urls: list[str] = []

    async def mock_fetch_html(url):
        fetched_urls.append(url)
        # Return minimal HTML with a form so the tool records observations
        return '<form action="/submit" method="POST"><input name="email"></form>'

    # Patch DB query to return 25 URL assets
    mock_result = MagicMock()
    mock_result.all.return_value = url_assets
    mock_execute = AsyncMock(return_value=mock_result)
    mock_session = MagicMock()
    mock_session.execute = mock_execute
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    target = MagicMock(base_domain="example.com")

    with patch("workers.info_gathering.tools.form_mapper.get_session", mock_get_session), \
         patch.object(tool, "_fetch_html", side_effect=mock_fetch_html), \
         patch.object(tool, "save_observation", new=AsyncMock()), \
         patch.object(tool, "_write_parameters", new=AsyncMock()):
        await tool.execute(target_id=1, target=target)

    # Should have processed all 26 URLs (25 from DB + 1 base domain prepended)
    assert len(fetched_urls) == 26, (
        f"FormMapper processed {len(fetched_urls)} URLs, expected 26"
    )


# ---------------------------------------------------------------------------
# Katana unit tests
# ---------------------------------------------------------------------------

from workers.info_gathering.tools.katana import Katana
from workers.info_gathering.tools.execution_path_analyzer import CrawlResult


@pytest.mark.anyio
async def test_katana_uses_host_not_base_domain():
    """Katana must crawl `host` kwarg, not target.base_domain."""
    tool = Katana()
    target = MagicMock(base_domain="base.com")
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        result = await tool.execute(
            target_id=1,
            target=target,
            host="api.base.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert captured_cmds, "run_subprocess was never called"
    all_args = " ".join(captured_cmds[0])
    assert "api.base.com" in all_args
    assert "https://base.com" not in all_args


@pytest.mark.anyio
async def test_katana_intensity_low_sets_depth_2():
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            intensity="low",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert "-d" in cmd
    assert cmd[cmd.index("-d") + 1] == "2"


@pytest.mark.anyio
async def test_katana_intensity_high_sets_depth_5():
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            intensity="high",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert cmd[cmd.index("-d") + 1] == "5"


@pytest.mark.anyio
async def test_katana_feeds_ws_seeds_as_additional_urls():
    """WS seed URLs must appear as additional -u args in the Katana command."""
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            ws_seeds=["wss://example.com/ws", "ws://example.com/events"],
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert "wss://example.com/ws" in cmd
    assert "ws://example.com/events" in cmd


@pytest.mark.anyio
async def test_katana_scope_check_filters_out_of_scope_urls():
    """URLs that fail scope_check must not be saved as assets."""
    tool = Katana()

    katana_output = '{"url": "https://evil.com/page"}\n{"url": "https://example.com/safe"}'

    scope_manager = MagicMock(_in_scope_patterns={"example.com"})
    scope_manager.classify = MagicMock(side_effect=lambda url: MagicMock(
        classification="in-scope" if "example.com" in url else "out-of-scope"
    ))

    saved: list[str] = []

    async def mock_save(target_id, asset_type, url, source, **kwargs):
        saved.append(url)
        return 1

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=katana_output)), \
         patch.object(tool, "save_asset", side_effect=mock_save):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=scope_manager,
        )

    assert "https://evil.com/page" not in saved
    assert "https://example.com/safe" in saved


@pytest.mark.anyio
async def test_katana_saves_ws_url_as_websocket_asset_type():
    """A wss:// URL discovered during crawl is saved as asset_type='websocket'."""
    tool = Katana()

    katana_output = '{"url": "wss://example.com/ws"}'

    saved_types: list[tuple[str, str]] = []

    async def mock_save(target_id, asset_type, url, source, **kwargs):
        saved_types.append((asset_type, url))
        return 1

    scope_manager = MagicMock(_in_scope_patterns=set())

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=katana_output)), \
         patch.object(tool, "save_asset", side_effect=mock_save):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=scope_manager,
        )

    assert ("websocket", "wss://example.com/ws") in saved_types


@pytest.mark.anyio
async def test_katana_returns_crawl_result():
    """Katana.execute must return a CrawlResult instance."""
    tool = Katana()

    katana_output = '{"url": "https://example.com/page"}\n{"url": "wss://example.com/ws"}'

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=katana_output)), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.tool == "katana"
    assert result.error is None
    assert "https://example.com/page" in result.urls
    assert "wss://example.com/ws" in result.ws_urls


@pytest.mark.anyio
async def test_katana_headers_forwarded_as_H_flags():
    """Custom headers must appear as -H 'Key: Value' in the Katana command."""
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            headers={"Cookie": "session=abc123", "X-Custom": "value"},
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    cmd_str = " ".join(cmd)
    assert "Cookie: session=abc123" in cmd_str
    assert "X-Custom: value" in cmd_str


@pytest.mark.anyio
async def test_katana_returns_crawl_result_with_error_on_subprocess_failure():
    """On subprocess failure, Katana returns CrawlResult with error set."""
    tool = Katana()

    with patch.object(tool, "run_subprocess", side_effect=TimeoutError("timed out")):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.error is not None
    assert "timed out" in result.error
    assert result.urls == []


# ---------------------------------------------------------------------------
# Hakrawler unit tests
# ---------------------------------------------------------------------------

from workers.info_gathering.tools.hakrawler import Hakrawler


@pytest.mark.anyio
async def test_hakrawler_uses_host_not_base_domain():
    """Hakrawler must crawl `host` kwarg, not target.base_domain."""
    tool = Hakrawler()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="base.com"),
            host="api.base.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert captured_cmds, "run_subprocess was never called"
    all_args = " ".join(captured_cmds[0])
    assert "api.base.com" in all_args
    assert "https://base.com" not in all_args


@pytest.mark.anyio
async def test_hakrawler_intensity_medium_sets_depth_3():
    tool = Hakrawler()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            intensity="medium",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert "-depth" in cmd
    assert cmd[cmd.index("-depth") + 1] == "3"


@pytest.mark.anyio
async def test_hakrawler_returns_crawl_result():
    """Hakrawler.execute must return a CrawlResult instance."""
    tool = Hakrawler()

    output = "https://example.com/page1\nhttps://example.com/page2\n"

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=output)), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.tool == "hakrawler"
    assert result.error is None
    assert "https://example.com/page1" in result.urls


@pytest.mark.anyio
async def test_hakrawler_returns_error_on_subprocess_failure():
    tool = Hakrawler()

    with patch.object(tool, "run_subprocess", side_effect=TimeoutError("timeout")):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.error is not None
    assert result.urls == []


# ---------------------------------------------------------------------------
# ExecutionPathAnalyzer unit tests
# ---------------------------------------------------------------------------

from workers.info_gathering.tools.execution_path_analyzer import (
    ExecutionPathAnalyzer,
    _categorize,
)


def test_analyzer_categorizes_auth_flow_urls():
    assert _categorize("https://example.com/login") == "auth_flow"


def test_analyzer_categorizes_admin_panel_urls():
    assert _categorize("https://example.com/admin/dashboard") == "admin_panel"


def test_analyzer_categorizes_api_endpoint_urls():
    assert _categorize("https://example.com/api/v1/users") == "api_endpoint"


def test_analyzer_categorizes_websocket_urls():
    assert _categorize("wss://example.com/ws") == "websocket"


def test_analyzer_first_matching_bucket_wins():
    # "wss://" appears first in _CATEGORIES (websocket), before "api_endpoint"
    assert _categorize("wss://example.com/api/ws") == "websocket"


def test_analyzer_categorizes_other_urls():
    assert _categorize("https://example.com/some/page") == "other"


@pytest.mark.anyio
async def test_analyzer_writes_summary_observation_with_correct_asset_id():
    analyzer = ExecutionPathAnalyzer(asset_id=99, target_id=1)

    mock_obs_id = 42
    captured_obs: list = []

    mock_session = MagicMock()
    mock_session.add = MagicMock(side_effect=lambda obs: captured_obs.append(obs))
    mock_session.commit = AsyncMock()

    async def set_obs_id(obs):
        obs.id = mock_obs_id

    mock_session.refresh = AsyncMock(side_effect=set_obs_id)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    with patch(
        "workers.info_gathering.tools.execution_path_analyzer.get_session",
        mock_get_session,
    ):
        result = await analyzer.write_summary(
            [CrawlResult(tool="katana", urls=["https://example.com/page"])],
            intensity="low",
        )

    assert result == mock_obs_id
    assert len(captured_obs) == 1
    assert captured_obs[0].asset_id == 99


@pytest.mark.anyio
async def test_analyzer_partial_true_when_both_crawlers_error():
    analyzer = ExecutionPathAnalyzer(asset_id=1, target_id=1)

    mock_session = MagicMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    saved_tech_stack: list[dict] = []

    async def capture_refresh(obs):
        obs.id = 1
        saved_tech_stack.append(obs.tech_stack)

    mock_session.refresh = AsyncMock(side_effect=capture_refresh)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    crawl_results = [
        CrawlResult(tool="katana", error="timeout"),
        CrawlResult(tool="hakrawler", error="fail"),
    ]

    with patch(
        "workers.info_gathering.tools.execution_path_analyzer.get_session",
        mock_get_session,
    ):
        await analyzer.write_summary(crawl_results, intensity="low")

    assert saved_tech_stack, "refresh was never called"
    assert saved_tech_stack[0].get("partial") is True


@pytest.mark.anyio
async def test_analyzer_partial_true_when_one_crawler_errors():
    analyzer = ExecutionPathAnalyzer(asset_id=1, target_id=1)

    mock_session = MagicMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    saved_tech_stack: list[dict] = []

    async def capture_refresh(obs):
        obs.id = 2
        saved_tech_stack.append(obs.tech_stack)

    mock_session.refresh = AsyncMock(side_effect=capture_refresh)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    crawl_results = [
        CrawlResult(tool="katana", error="timeout"),
        CrawlResult(tool="hakrawler", urls=["https://example.com/page"]),
    ]

    with patch(
        "workers.info_gathering.tools.execution_path_analyzer.get_session",
        mock_get_session,
    ):
        await analyzer.write_summary(crawl_results, intensity="low")

    assert saved_tech_stack, "refresh was never called"
    assert saved_tech_stack[0].get("partial") is True


@pytest.mark.anyio
async def test_analyzer_tool_breakdown_reflects_per_tool_counts():
    analyzer = ExecutionPathAnalyzer(asset_id=1, target_id=1)

    mock_session = MagicMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    saved_tech_stack: list[dict] = []

    async def capture_refresh(obs):
        obs.id = 3
        saved_tech_stack.append(obs.tech_stack)

    mock_session.refresh = AsyncMock(side_effect=capture_refresh)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    crawl_results = [
        CrawlResult(
            tool="katana",
            urls=["https://example.com/a", "https://example.com/b", "https://example.com/c"],
        ),
        CrawlResult(
            tool="hakrawler",
            urls=["https://example.com/x", "https://example.com/y"],
        ),
    ]

    with patch(
        "workers.info_gathering.tools.execution_path_analyzer.get_session",
        mock_get_session,
    ):
        await analyzer.write_summary(crawl_results, intensity="medium")

    assert saved_tech_stack, "refresh was never called"
    breakdown = saved_tech_stack[0]["tool_breakdown"]
    assert breakdown["katana"]["total"] == 3
    assert breakdown["katana"]["errored"] is False
    assert breakdown["hakrawler"]["total"] == 2
    assert breakdown["hakrawler"]["errored"] is False


# ---------------------------------------------------------------------------
# Pipeline Stage 7 hook unit tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_pipeline_fetch_ws_seeds_returns_websocket_assets():
    """_fetch_ws_seeds must query DB for asset_type='websocket' under target_id."""
    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=5, container_name="info_gathering")

    from lib_webbh.database import Base, Asset, Target
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as sess:
        t = Target(id=5, company_name="Test", base_domain="example.com")
        sess.add(t)
        await sess.flush()
        ws1 = Asset(target_id=5, asset_type="websocket", asset_value="wss://example.com/ws")
        ws2 = Asset(target_id=5, asset_type="websocket", asset_value="ws://example.com/events")
        other = Asset(target_id=5, asset_type="domain", asset_value="https://example.com/page")
        sess.add_all([ws1, ws2, other])
        await sess.commit()

    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    with patch("workers.info_gathering.pipeline.get_session", fake_session):
        seeds = await pipeline._fetch_ws_seeds(5)

    assert "wss://example.com/ws" in seeds
    assert "ws://example.com/events" in seeds
    assert "https://example.com/page" not in seeds

    await engine.dispose()
