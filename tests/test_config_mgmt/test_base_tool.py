"""Tests for config management base_tool module."""
import os
import pytest
from abc import ABC
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from workers.config_mgmt.base_tool import ConfigMgmtTool

    assert issubclass(ConfigMgmtTool, ABC)

    with pytest.raises(TypeError):
        ConfigMgmtTool()


def test_concrete_tool_implements_abstract_methods():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
    assert tool.name == "NetworkConfigTester"


@pytest.mark.anyio
async def test_run_subprocess_returns_string():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
    result = await tool.run_subprocess(["echo", "hello"])
    assert isinstance(result, str)
    assert "hello" in result


@pytest.mark.anyio
async def test_check_cooldown_returns_false_when_no_history():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("workers.config_mgmt.base_tool.get_session", return_value=mock_session):
        result = await tool.check_cooldown(target_id=1, container_name="test")
    assert result is False


@pytest.mark.anyio
async def test_execute_returns_stats_dict():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
    target = MagicMock(base_domain="example.com")
    scope_mgr = MagicMock()

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    mock_heavy = AsyncMock()
    mock_light = AsyncMock()

    with patch.object(tool, "check_cooldown", return_value=False):
        with patch.object(tool, "run_subprocess", return_value="test output"):
            with patch.object(tool, "_process_result", return_value=True):
                with patch("workers.config_mgmt.base_tool.push_task", new_callable=AsyncMock):
                    with patch("workers.config_mgmt.base_tool.get_session", return_value=mock_session):
                        with patch("workers.config_mgmt.concurrency.get_semaphores") as mock_sem:
                            mock_sem.return_value = (mock_heavy, mock_light)
                            stats = await tool.execute(
                                target=target,
                                scope_manager=scope_mgr,
                                target_id=1,
                                container_name="test",
                            )
    assert isinstance(stats, dict)
    assert "found" in stats
    assert "in_scope" in stats
    assert "new" in stats
    assert "skipped_cooldown" in stats


@pytest.mark.anyio
async def test_execute_skips_on_cooldown():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
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
    assert stats["new"] == 0


def test_check_response_for_info_leak():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
    response = "password=secret123 api_key=abc123 normal text"
    leaks = tool.check_response_for_info_leak(response)
    assert isinstance(leaks, list)
    assert len(leaks) > 0


def test_compare_responses_different():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
    assert tool.compare_responses("hello", "world") is True


def test_compare_responses_same():
    from workers.config_mgmt.tools import NetworkConfigTester

    tool = NetworkConfigTester()
    assert tool.compare_responses("hello", "hello") is False
