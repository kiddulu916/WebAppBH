"""Tests for client-side base_tool module."""
import os
import sys
import pytest
from abc import ABC
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    with patch.dict(sys.modules, {"playwright.async_api": MagicMock()}):
        from workers.client_side.base_tool import ClientSideTool

        assert issubclass(ClientSideTool, ABC)

        with pytest.raises(TypeError):
            ClientSideTool()


def test_concrete_tool_implements_abstract_methods():
    with patch.dict(sys.modules, {"playwright.async_api": MagicMock()}):
        from workers.client_side.tools import DomXssTester

        tool = DomXssTester()
        assert tool.name == "dom_xss_tester"


@pytest.mark.anyio
async def test_run_subprocess_returns_string():
    with patch.dict(sys.modules, {"playwright.async_api": MagicMock()}):
        from workers.client_side.tools import DomXssTester

        tool = DomXssTester()
        result = await tool.run_subprocess(["echo", "hello"])
        assert isinstance(result, str)
        assert "hello" in result


@pytest.mark.anyio
async def test_check_cooldown_returns_false_when_no_history():
    with patch.dict(sys.modules, {"playwright.async_api": MagicMock()}):
        from workers.client_side.tools import DomXssTester

        tool = DomXssTester()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("workers.client_side.base_tool.get_session", return_value=mock_session):
            result = await tool.check_cooldown(target_id=1, container_name="test")
        assert result is False


@pytest.mark.anyio
async def test_execute_returns_stats_dict():
    with patch.dict(sys.modules, {"playwright.async_api": MagicMock()}):
        from workers.client_side.tools import DomXssTester

        tool = DomXssTester()
        target = MagicMock(base_domain="example.com")
        scope_mgr = MagicMock()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch.object(tool, "check_cooldown", return_value=False):
            with patch.object(tool, "run_subprocess", return_value="test output"):
                with patch("workers.client_side.base_tool.push_task", new_callable=AsyncMock):
                    with patch("workers.client_side.base_tool.get_session", return_value=mock_session):
                        stats = await tool.execute(
                            target=target,
                            scope_manager=scope_mgr,
                            target_id=1,
                            container_name="test",
                        )
        assert isinstance(stats, dict)
        assert "found" in stats
        assert "inserted" in stats
        assert "skipped_cooldown" in stats


@pytest.mark.anyio
async def test_execute_skips_on_cooldown():
    with patch.dict(sys.modules, {"playwright.async_api": MagicMock()}):
        from workers.client_side.tools import DomXssTester

        tool = DomXssTester()
        target = MagicMock(base_domain="example.com")
        scope_mgr = MagicMock()

        with patch.object(tool, "check_cooldown", return_value=True):
            stats = await tool.execute(
                target=target,
                scope_manager=scope_mgr,
                target_id=1,
                container_name="test",
            )
        assert stats["skipped_cooldown"] is True
        assert stats["found"] == 0
        assert stats["inserted"] == 0
