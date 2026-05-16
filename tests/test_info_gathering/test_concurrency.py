# tests/test_info_gathering/test_concurrency.py
import asyncio


def test_get_semaphores_returns_bounded_semaphores():
    from workers.info_gathering.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.Semaphore)
    assert isinstance(light, asyncio.Semaphore)


def test_tool_weights_contains_all_tools():
    from workers.info_gathering.concurrency import TOOL_WEIGHTS
    from workers.info_gathering.pipeline import STAGES

    # Every tool class used in the pipeline must have a concurrency weight
    pipeline_tools = {cls.__name__ for stage in STAGES for cls in stage.tools}
    assert pipeline_tools == set(TOOL_WEIGHTS.keys())


def test_tool_weights_valid_values():
    from workers.info_gathering.concurrency import TOOL_WEIGHTS

    for tool, weight in TOOL_WEIGHTS.items():
        assert weight in ("HEAVY", "LIGHT"), f"{tool} has invalid weight: {weight}"