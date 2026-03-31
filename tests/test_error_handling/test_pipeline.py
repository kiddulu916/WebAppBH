# tests/test_error_handling/test_pipeline.py
import pytest

pytestmark = pytest.mark.anyio


def test_pipeline_stages_defined():
    from workers.error_handling.pipeline import STAGES

    assert len(STAGES) == 2
    assert all(hasattr(s, "name") for s in STAGES)
    assert all(hasattr(s, "section_id") for s in STAGES)
    assert all(hasattr(s, "tools") for s in STAGES)


def test_pipeline_stages_ordered():
    from workers.error_handling.pipeline import STAGES

    section_ids = [s.section_id for s in STAGES]
    # Verify stages are in WSTG section order
    assert section_ids == ["4.8.1", "4.8.2"]


def test_pipeline_all_tools_have_weights():
    from workers.error_handling.pipeline import STAGES
    from workers.error_handling.concurrency import TOOL_WEIGHTS

    all_tools = set()
    for stage in STAGES:
        for tool_cls in stage.tools:
            all_tools.add(tool_cls.__name__)

    assert all_tools == set(TOOL_WEIGHTS.keys())