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


# ---------------------------------------------------------------------------
# WebAppTool base class tests
# ---------------------------------------------------------------------------


async def _create_tables():
    """Create all tables in the in-memory sqlite DB."""
    from lib_webbh.database import Base, get_engine

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def _make_dummy_tool():
    """Return a concrete DummyTool subclass of WebAppTool."""
    from workers.webapp_worker.base_tool import ToolType, WebAppTool
    from workers.webapp_worker.concurrency import WeightClass

    class DummyTool(WebAppTool):
        name = "dummy-tool"
        tool_type = ToolType.CLI
        weight_class = WeightClass.LIGHT

        async def execute(self, target, scope_manager, target_id, container_name,
                          headers=None, **kwargs):
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

    return DummyTool()


@pytest.mark.anyio
async def test_base_tool_check_cooldown_returns_false_when_no_job():
    """check_cooldown returns False when no matching JobState exists."""
    await _create_tables()

    tool = _make_dummy_tool()
    result = await tool.check_cooldown(999, "test-container")
    assert result is False


@pytest.mark.anyio
async def test_base_tool_save_vulnerability_creates_alert_for_critical():
    """_save_vulnerability with severity='critical' must create an Alert row."""
    await _create_tables()

    from lib_webbh import Alert, Asset, Target, get_session
    from sqlalchemy import select

    # Seed a Target + Asset
    async with get_session() as session:
        target = Target(company_name="Acme", base_domain="acme.com")
        session.add(target)
        await session.flush()
        target_id = target.id

        asset = Asset(
            target_id=target_id,
            asset_type="domain",
            asset_value="app.acme.com",
            source_tool="seed",
        )
        session.add(asset)
        await session.flush()
        asset_id = asset.id
        await session.commit()

    tool = _make_dummy_tool()

    with patch("workers.webapp_worker.base_tool.push_task", new_callable=AsyncMock) as mock_push:
        vuln_id = await tool._save_vulnerability(
            target_id=target_id,
            asset_id=asset_id,
            severity="critical",
            title="SQL Injection in login",
            description="The login form is vulnerable to SQL injection.",
            poc="' OR 1=1 --",
        )

    assert vuln_id is not None
    assert isinstance(vuln_id, int)

    # Verify Alert row was created
    async with get_session() as session:
        stmt = select(Alert).where(Alert.target_id == target_id)
        result = await session.execute(stmt)
        alerts = result.scalars().all()
        assert len(alerts) == 1
        assert "SQL Injection" in alerts[0].message

    # Verify push_task was called for SSE
    mock_push.assert_awaited_once()
