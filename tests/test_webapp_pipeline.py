import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


# ---------------------------------------------------------------------------
# BrowserManager tests
# ---------------------------------------------------------------------------


def _make_mock_page() -> MagicMock:
    """Return a mock page whose async methods are AsyncMocks."""
    page = MagicMock()
    page.close = AsyncMock()
    page.set_extra_http_headers = AsyncMock()
    # set_default_timeout is synchronous in Playwright
    page.set_default_timeout = MagicMock()
    return page


@pytest.mark.anyio
async def test_browser_manager_new_page_acquires_semaphore():
    """new_page() should decrement the semaphore value by one."""
    from workers.webapp_worker.browser import BrowserManager

    mgr = BrowserManager(max_tabs=3, page_timeout=10)

    mock_page = _make_mock_page()
    mock_browser = MagicMock()
    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mgr._browser = mock_browser

    assert mgr._sem._value == 3

    page = await mgr.new_page()

    assert mgr._sem._value == 2
    assert page is mock_page


@pytest.mark.anyio
async def test_browser_manager_release_page_frees_semaphore():
    """release_page() should restore the semaphore value."""
    from workers.webapp_worker.browser import BrowserManager

    mgr = BrowserManager(max_tabs=3, page_timeout=10)

    mock_page = _make_mock_page()
    mock_browser = MagicMock()
    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mgr._browser = mock_browser

    page = await mgr.new_page()
    assert mgr._sem._value == 2

    await mgr.release_page(page)
    assert mgr._sem._value == 3


@pytest.mark.anyio
async def test_browser_manager_injects_custom_headers():
    """new_page(headers=...) should call set_extra_http_headers on the page."""
    from workers.webapp_worker.browser import BrowserManager

    mgr = BrowserManager(max_tabs=3, page_timeout=10)

    mock_page = _make_mock_page()
    mock_browser = MagicMock()
    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mgr._browser = mock_browser

    headers = {"Authorization": "Bearer tok123", "X-Custom": "value"}
    page = await mgr.new_page(headers=headers)

    mock_page.set_extra_http_headers.assert_awaited_once_with(headers)
