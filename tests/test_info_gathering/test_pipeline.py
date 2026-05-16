# tests/test_info_gathering/test_pipeline.py
import pytest

pytestmark = pytest.mark.anyio


def test_pipeline_stages_defined():
    from workers.info_gathering.pipeline import STAGES

    assert len(STAGES) == 12
    assert all(hasattr(s, "name") for s in STAGES)
    assert all(hasattr(s, "section_id") for s in STAGES)
    assert all(hasattr(s, "tools") for s in STAGES)


def test_pipeline_stages_ordered():
    from workers.info_gathering.pipeline import STAGES

    names = [s.name for s in STAGES]
    # Verify all expected stage names are present
    expected_names = {
        "search_engine_recon", "web_server_fingerprint", "web_server_metafiles",
        "enumerate_applications", "review_comments", "identify_entry_points",
        "aggregate_entry_points", "map_execution_paths", "review_comments_deep",
        "fingerprint_framework", "map_architecture", "map_application",
    }
    assert set(names) == expected_names
    # Verify high-level ordering: entry-point discovery before path mapping
    assert names.index("identify_entry_points") < names.index("map_execution_paths")
    assert names.index("aggregate_entry_points") == names.index("identify_entry_points") + 1


def test_pipeline_all_tools_have_weights():
    from workers.info_gathering.pipeline import STAGES
    from workers.info_gathering.concurrency import TOOL_WEIGHTS

    all_tools = set()
    for stage in STAGES:
        for tool_cls in stage.tools:
            all_tools.add(tool_cls.__name__)

    assert all_tools == set(TOOL_WEIGHTS.keys())