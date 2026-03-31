# tests/test_business_logic/test_concurrency.py
import asyncio


def test_get_semaphores_returns_bounded_semaphores():
    from workers.business_logic.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.Semaphore)
    assert isinstance(light, asyncio.Semaphore)


def test_tool_weights_contains_all_tools():
    from workers.business_logic.concurrency import TOOL_WEIGHTS

    # Every tool must have a weight entry
    expected_tools = {"BusinessValidationTester", "RequestForgeryTester", "IntegrityTester", "TimingAnalyzer", "RateLimitTester", "WorkflowBypassTester", "MisuseTester", "FileTypeTester", "MaliciousUploadTester"}
    assert set(TOOL_WEIGHTS.keys()) == expected_tools


def test_tool_weights_valid_values():
    from workers.business_logic.concurrency import TOOL_WEIGHTS

    for tool, weight in TOOL_WEIGHTS.items():
        assert weight in ("HEAVY", "LIGHT"), f"{tool} has invalid weight: {weight}"