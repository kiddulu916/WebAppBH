# tests/test_messaging_listen_priority.py
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


async def test_listen_priority_queues_yields_messages():
    from lib_webbh.messaging import listen_priority_queues

    # Simulate: 1 critical message, then StopAsyncIteration
    call_count = 0

    async def mock_xreadgroup(groupname, consumername, streams, count, block):
        nonlocal call_count
        call_count += 1
        stream_name = list(streams.keys())[0]
        if call_count == 1 and stream_name.endswith(":critical"):
            return [(stream_name, [("msg-1", {"payload": '{"target_id": 1}'})])]
        return []

    mock_redis = AsyncMock()
    mock_redis.xreadgroup = mock_xreadgroup
    mock_redis.xgroup_create = AsyncMock()

    messages = []
    with patch("lib_webbh.messaging.get_redis", return_value=mock_redis):
        async for msg in listen_priority_queues(
            "config_mgmt_queue", "test_group", "test_consumer"
        ):
            messages.append(msg)
            if len(messages) >= 1:
                break

    assert len(messages) == 1
    assert messages[0]["payload"]["target_id"] == 1
    assert messages[0]["stream"].endswith(":critical")


async def test_listen_priority_queues_order():
    """Critical messages are yielded before low messages."""
    from lib_webbh.messaging import listen_priority_queues

    async def mock_xreadgroup(groupname, consumername, streams, count, block):
        stream_name = list(streams.keys())[0]
        if stream_name.endswith(":critical"):
            return [(stream_name, [("c1", {"payload": '{"p": "critical"}'})])]
        elif stream_name.endswith(":high"):
            return [(stream_name, [("h1", {"payload": '{"p": "high"}'})])]
        elif stream_name.endswith(":normal"):
            return [(stream_name, [("n1", {"payload": '{"p": "normal"}'})])]
        elif stream_name.endswith(":low"):
            return [(stream_name, [("l1", {"payload": '{"p": "low"}'})])]
        return []

    mock_redis = AsyncMock()
    mock_redis.xreadgroup = mock_xreadgroup
    mock_redis.xgroup_create = AsyncMock()

    messages = []
    with patch("lib_webbh.messaging.get_redis", return_value=mock_redis):
        async for msg in listen_priority_queues("q", "g", "c"):
            messages.append(msg)
            if len(messages) >= 4:
                break

    # Critical should come first, then high, normal, low
    priorities = [m["payload"]["p"] for m in messages]
    assert priorities == ["critical", "high", "normal", "low"]
