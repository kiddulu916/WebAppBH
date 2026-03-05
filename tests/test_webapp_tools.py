import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


# ---------------------------------------------------------------------------
# JsCrawler tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_js_crawler_executes_with_mocked_browser(tmp_path):
    """JsCrawler should crawl pages, capture JS responses, and save inline scripts."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()

    # ---- Mock BrowserManager ----
    browser_mgr = MagicMock()
    mock_page = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.on = MagicMock()  # page.on is synchronous (registers callback)
    mock_page.evaluate = AsyncMock(return_value=["var x = 1;"])
    mock_page.close = AsyncMock()
    browser_mgr.new_page = AsyncMock(return_value=mock_page)
    browser_mgr.release_page = AsyncMock()

    # ---- Mock scope_manager ----
    scope_mgr = MagicMock()

    with (
        patch.object(
            crawler, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
        patch.object(
            crawler, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            crawler, "update_tool_state", new_callable=AsyncMock,
        ),
        patch.object(
            crawler, "_save_asset", new_callable=AsyncMock,
            return_value=10,
        ),
        patch("workers.webapp_worker.tools.js_crawler.JS_DIR", str(tmp_path)),
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            headers={"User-Agent": "TestBot"},
            browser=browser_mgr,
        )

    # Verify cooldown not skipped
    assert result["skipped_cooldown"] is False

    # Verify browser interaction
    browser_mgr.new_page.assert_awaited()
    browser_mgr.release_page.assert_awaited()

    # Verify page.goto was called with https first
    mock_page.goto.assert_awaited()
    goto_url = mock_page.goto.call_args_list[0][0][0]
    assert goto_url.startswith("https://")

    # Verify page.on was called to register response handler
    mock_page.on.assert_called()

    # Verify inline scripts were extracted via evaluate
    mock_page.evaluate.assert_awaited()

    # Verify JS output directory was created
    js_dir = tmp_path / "42" / "js"
    assert js_dir.exists()

    # Verify inline script was saved
    inline_files = list(js_dir.glob("inline_*.js"))
    assert len(inline_files) == 1
    assert inline_files[0].read_text() == "var x = 1;"


@pytest.mark.anyio
async def test_js_crawler_skips_on_cooldown(tmp_path):
    """JsCrawler returns early with skipped_cooldown=True when within cooldown."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()
    scope_mgr = MagicMock()

    with patch.object(
        crawler, "check_cooldown", new_callable=AsyncMock,
        return_value=True,
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
        )

    assert result["skipped_cooldown"] is True


@pytest.mark.anyio
async def test_js_crawler_returns_early_without_browser(tmp_path):
    """JsCrawler returns early when no browser kwarg is provided."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()
    scope_mgr = MagicMock()

    with (
        patch.object(
            crawler, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            crawler, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            # No browser= kwarg
        )

    assert result["skipped_cooldown"] is False
    assert result["js_files_saved"] == 0


@pytest.mark.anyio
async def test_js_crawler_falls_back_to_http(tmp_path):
    """JsCrawler tries http when https page.goto raises an exception."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()

    browser_mgr = MagicMock()
    mock_page = MagicMock()

    # First call (https) raises, second call (http) succeeds
    mock_page.goto = AsyncMock(
        side_effect=[Exception("Connection refused"), None]
    )
    mock_page.on = MagicMock()
    mock_page.evaluate = AsyncMock(return_value=[])
    mock_page.close = AsyncMock()
    browser_mgr.new_page = AsyncMock(return_value=mock_page)
    browser_mgr.release_page = AsyncMock()

    scope_mgr = MagicMock()

    with (
        patch.object(
            crawler, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
        patch.object(
            crawler, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            crawler, "update_tool_state", new_callable=AsyncMock,
        ),
        patch.object(
            crawler, "_save_asset", new_callable=AsyncMock,
            return_value=10,
        ),
        patch("workers.webapp_worker.tools.js_crawler.JS_DIR", str(tmp_path)),
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            browser=browser_mgr,
        )

    # Both https and http were attempted
    assert mock_page.goto.await_count == 2
    goto_calls = [c[0][0] for c in mock_page.goto.call_args_list]
    assert goto_calls[0].startswith("https://")
    assert goto_calls[1].startswith("http://")

    # release_page still called (cleanup)
    browser_mgr.release_page.assert_awaited()


@pytest.mark.anyio
async def test_js_crawler_class_attributes():
    """Verify JsCrawler has correct class-level attributes."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler
    from workers.webapp_worker.base_tool import ToolType
    from workers.webapp_worker.concurrency import WeightClass

    assert JsCrawler.name == "js_crawler"
    assert JsCrawler.tool_type == ToolType.BROWSER
    assert JsCrawler.weight_class == WeightClass.HEAVY
