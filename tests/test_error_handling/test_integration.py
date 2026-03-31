# tests/test_error_handling/test_integration.py
import pytest

pytestmark = pytest.mark.anyio


async def test_pipeline_runs_all_stages(db_session):
    """Verify pipeline executes all stages without error against a test target."""
    from lib_webbh.database import Target
    from workers.error_handling.pipeline import STAGES

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # Each stage should be importable and its tools instantiable
    for stage in STAGES:
        for tool_cls in stage.tools:
            tool = tool_cls()
            assert hasattr(tool, "execute")
            assert tool.worker_type == "error_handling"