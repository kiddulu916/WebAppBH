# tests/test_cryptography/test_pipeline.py
import pytest

pytestmark = pytest.mark.anyio


def test_pipeline_stages_defined():
    from workers.cryptography.pipeline import STAGES

    assert len(STAGES) == 4
    assert all(hasattr(s, "name") for s in STAGES)
    assert all(hasattr(s, "section_id") for s in STAGES)
    assert all(hasattr(s, "tools") for s in STAGES)


def test_pipeline_stages_ordered():
    from workers.cryptography.pipeline import STAGES

    section_ids = [s.section_id for s in STAGES]
    # Verify stages are in WSTG section order
    assert section_ids == ["4.9.1", "4.9.2", "4.9.3", "4.9.4"]


def test_pipeline_all_tools_have_weights():
    from workers.cryptography.pipeline import STAGES
    from workers.cryptography.concurrency import TOOL_WEIGHTS

    all_tools = set()
    for stage in STAGES:
        for tool_cls in stage.tools:
            all_tools.add(tool_cls.__name__)

    assert all_tools == set(TOOL_WEIGHTS.keys())