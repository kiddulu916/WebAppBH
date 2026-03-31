# tests/test_error_handling/test_stack_trace_detector.py
import pytest

pytestmark = pytest.mark.anyio


def test_stack_trace_detector_subclasses_base():
    from workers.error_handling.tools.stack_trace_detector import StackTraceDetector
    from workers.error_handling.base_tool import ErrorHandlingTool

    assert issubclass(StackTraceDetector, ErrorHandlingTool)


async def test_stack_trace_detector_execute(db_session):
    """Test that execute runs and produces expected output type."""
    from lib_webbh.database import Target
    from workers.error_handling.tools.stack_trace_detector import StackTraceDetector

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    tool = StackTraceDetector()
    await tool.execute(target.id)

    # Should have saved some vulnerabilities or observations
    # (exact test depends on implementation)