# tests/test_messaging_priority.py
import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.anyio


async def test_push_priority_task_critical():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-123"

        result = await push_priority_task(
            "config_mgmt_queue",
            {"target_id": 1, "worker": "config_mgmt"},
            priority_score=95,
        )

        mock_push.assert_called_once_with(
            "config_mgmt_queue:critical",
            {"target_id": 1, "worker": "config_mgmt"},
        )
        assert result == "msg-123"


async def test_push_priority_task_high():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-456"
        await push_priority_task("queue", {"data": 1}, priority_score=75)
        mock_push.assert_called_once_with("queue:high", {"data": 1})


async def test_push_priority_task_normal():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-789"
        await push_priority_task("queue", {"data": 1}, priority_score=55)
        mock_push.assert_called_once_with("queue:normal", {"data": 1})


async def test_push_priority_task_low():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-000"
        await push_priority_task("queue", {"data": 1}, priority_score=30)
        mock_push.assert_called_once_with("queue:low", {"data": 1})


async def test_push_priority_task_boundary_90():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg"
        await push_priority_task("queue", {}, priority_score=90)
        mock_push.assert_called_once_with("queue:critical", {})


async def test_push_priority_task_boundary_70():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg"
        await push_priority_task("queue", {}, priority_score=70)
        mock_push.assert_called_once_with("queue:high", {})


async def test_push_priority_task_boundary_50():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg"
        await push_priority_task("queue", {}, priority_score=50)
        mock_push.assert_called_once_with("queue:normal", {})
