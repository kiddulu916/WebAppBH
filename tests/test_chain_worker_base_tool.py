# tests/test_chain_worker_base_tool.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass


def test_base_is_abstract():
    import inspect
    assert inspect.isabstract(ChainTestTool)


def test_constants():
    from workers.chain_worker.base_tool import TOOL_TIMEOUT, COOLDOWN_HOURS
    assert TOOL_TIMEOUT == 600
    assert COOLDOWN_HOURS == 24


@pytest.mark.anyio
async def test_take_screenshot_no_browser():
    from workers.chain_worker.base_tool import take_screenshot
    path = await take_screenshot(
        browser=None, url="http://example.com", output_path="/tmp/test.png",
    )
    assert path is None


@pytest.mark.anyio
async def test_step_delay():
    import time
    from workers.chain_worker.base_tool import step_delay
    os.environ["CHAIN_STEP_DELAY_MS"] = "50"
    start = time.monotonic()
    await step_delay()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.04
