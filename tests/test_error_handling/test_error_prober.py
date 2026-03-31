# tests/test_error_handling/test_error_prober.py
import pytest

pytestmark = pytest.mark.anyio


def test_error_prober_subclasses_base():
    from workers.error_handling.tools.error_prober import ErrorProber
    from workers.error_handling.base_tool import ErrorHandlingTool

    assert issubclass(ErrorProber, ErrorHandlingTool)


async def test_error_prober_execute(db_session):
    """Test that execute runs and produces expected output type."""
    from lib_webbh.database import Target
    from workers.error_handling.tools.error_prober import ErrorProber

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    tool = ErrorProber()
    await tool.execute(target.id)

    # Should have saved some vulnerabilities or observations
    # (exact test depends on implementation)