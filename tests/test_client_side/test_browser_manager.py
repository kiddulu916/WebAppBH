"""Tests for BrowserManager singleton."""
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


@pytest.fixture(autouse=True)
def mock_playwright():
    mock_pw_module = MagicMock()
    mock_pw_instance = MagicMock()
    mock_browser = AsyncMock()
    mock_chromium = MagicMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw_instance.chromium = mock_chromium
    mock_pw_module.start = AsyncMock(return_value=mock_pw_instance)
    mock_pw_module.return_value.start = AsyncMock(return_value=mock_pw_instance)

    with patch.dict(sys.modules, {"playwright.async_api": mock_pw_module}):
        with patch("workers.client_side.browser_manager.async_playwright", return_value=mock_pw_module):
            yield


@pytest.mark.anyio
async def test_browser_manager_singleton():
    from workers.client_side.browser_manager import BrowserManager

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}

    instance1 = await BrowserManager.get_instance()
    instance2 = await BrowserManager.get_instance()

    assert instance1 is instance2

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}


@pytest.mark.anyio
async def test_browser_manager_create_context():
    from workers.client_side.browser_manager import BrowserManager

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}

    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)

    manager = BrowserManager()
    manager._browser = mock_browser

    context = await manager.create_context(target_id=1)

    assert context is mock_context
    assert 1 in manager._contexts

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}


@pytest.mark.anyio
async def test_browser_manager_close_context():
    from workers.client_side.browser_manager import BrowserManager

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}

    mock_context = AsyncMock()
    manager = BrowserManager()
    manager._contexts[1] = mock_context

    await manager.close_context(target_id=1)

    assert 1 not in manager._contexts
    mock_context.close.assert_called_once()

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}


@pytest.mark.anyio
async def test_browser_manager_cleanup():
    from workers.client_side.browser_manager import BrowserManager

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}

    mock_context1 = AsyncMock()
    mock_context2 = AsyncMock()
    mock_browser = AsyncMock()

    manager = BrowserManager()
    manager._contexts[1] = mock_context1
    manager._contexts[2] = mock_context2
    manager._browser = mock_browser

    await manager.cleanup()

    assert len(manager._contexts) == 0
    mock_context1.close.assert_called_once()
    mock_context2.close.assert_called_once()
    mock_browser.close.assert_called_once()
    assert manager._browser is None

    BrowserManager._instance = None
    BrowserManager._browser = None
    BrowserManager._contexts = {}
