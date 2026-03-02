import asyncio
import json

import pytest
import pytest_asyncio

from lib_webbh.messaging import push_task, listen_queue, get_pending, get_redis
import lib_webbh.messaging as messaging_mod


@pytest_asyncio.fixture
async def redis_client():
    client = get_redis()
    yield client
    # Clean up stream and consumer groups
    try:
        await client.xgroup_destroy("test_queue", "test_group")
    except Exception:
        pass
    await client.delete("test_queue")
    # Reset the module-level singleton so next test gets a fresh one
    messaging_mod._redis = None
    await client.aclose()


@pytest.mark.asyncio
async def test_push_task_returns_message_id(redis_client):
    msg_id = await push_task("test_queue", {"target_id": 1, "action": "scan"})
    assert msg_id is not None
    assert isinstance(msg_id, str)
    assert "-" in msg_id


@pytest.mark.asyncio
async def test_push_and_consume(redis_client):
    received = []

    async def handler(message_id: str, data: dict) -> None:
        received.append(data)

    await push_task("test_queue", {"target_id": 1, "action": "test_consume"})

    listener_task = asyncio.create_task(
        listen_queue("test_queue", "test_group", "consumer_1", handler)
    )
    await asyncio.sleep(1)
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    assert len(received) == 1
    assert received[0]["action"] == "test_consume"


@pytest.mark.asyncio
async def test_get_pending_returns_empty_after_ack(redis_client):
    await push_task("test_queue", {"target_id": 2, "action": "pending_test"})

    async def handler(message_id: str, data: dict) -> None:
        pass

    listener_task = asyncio.create_task(
        listen_queue("test_queue", "test_group", "consumer_1", handler)
    )
    await asyncio.sleep(1)
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    pending = await get_pending("test_queue", "test_group")
    assert pending["pending"] == 0
