"""Tests for Stage 1 pipeline and concurrency registration."""

from workers.info_gathering.pipeline import STAGES
from workers.info_gathering.concurrency import TOOL_WEIGHTS


def test_stage1_has_six_tools():
    stage1 = STAGES[0]
    assert stage1.name == "search_engine_recon"
    assert len(stage1.tools) == 6


def test_new_tools_are_light_weight():
    for name in ["CacheProber", "ShodanSearcher", "CensysSearcher", "SecurityTrailsSearcher"]:
        assert TOOL_WEIGHTS[name] == "LIGHT"


def test_stage1_tool_names():
    stage1 = STAGES[0]
    tool_names = [cls.__name__ for cls in stage1.tools]
    assert "DorkEngine" in tool_names
    assert "ArchiveProber" in tool_names
    assert "CacheProber" in tool_names
    assert "ShodanSearcher" in tool_names
    assert "CensysSearcher" in tool_names
    assert "SecurityTrailsSearcher" in tool_names
