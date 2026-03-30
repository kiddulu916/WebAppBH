# tests/test_info_gathering/test_pipeline.py
import pytest

pytestmark = pytest.mark.anyio


def test_pipeline_stages_defined():
    from workers.info_gathering.pipeline import STAGES

    assert len(STAGES) == 10
    assert all(hasattr(s, "name") for s in STAGES)
    assert all(hasattr(s, "section_id") for s in STAGES)
    assert all(hasattr(s, "tools") for s in STAGES)


def test_pipeline_stages_ordered():
    from workers.info_gathering.pipeline import STAGES

    section_ids = [s.section_id for s in STAGES]
    # Verify stages are in WSTG section order (4.1.1 -> 4.1.10)
    expected = [f"4.1.{i}" for i in range(1, 11)]
    assert section_ids == expected


def test_pipeline_all_tools_have_weights():
    from workers.info_gathering.pipeline import STAGES
    from workers.info_gathering.concurrency import TOOL_WEIGHTS

    all_tools = set()
    for stage in STAGES:
        for tool_cls in stage.tools:
            all_tools.add(tool_cls.__name__)

    assert all_tools == set(TOOL_WEIGHTS.keys())