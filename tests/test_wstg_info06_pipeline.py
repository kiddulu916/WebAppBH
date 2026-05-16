"""Pipeline and concurrency registration tests for WSTG-INFO-06."""


def test_asset_types_includes_websocket_and_url():
    from lib_webbh.database import ASSET_TYPES
    assert "websocket" in ASSET_TYPES, "websocket missing from ASSET_TYPES"
    assert "url" in ASSET_TYPES, "url missing from ASSET_TYPES"


def test_identify_entry_points_stage_contains_websocket_prober():
    from workers.info_gathering.pipeline import STAGES
    from workers.info_gathering.tools.websocket_prober import WebSocketProber
    stage = next(s for s in STAGES if s.name == "identify_entry_points")
    assert WebSocketProber in stage.tools


def test_aggregate_entry_points_stage_exists_after_identify():
    from workers.info_gathering.pipeline import STAGES
    names = [s.name for s in STAGES]
    id_idx = names.index("identify_entry_points")
    agg_idx = names.index("aggregate_entry_points")
    assert agg_idx == id_idx + 1


def test_aggregate_entry_points_has_entry_point_aggregator():
    from workers.info_gathering.pipeline import STAGES
    from workers.info_gathering.tools.entry_point_aggregator import EntryPointAggregator
    stage = next(s for s in STAGES if s.name == "aggregate_entry_points")
    assert stage.tools == [EntryPointAggregator]


def test_aggregate_entry_points_shares_section_id_with_identify():
    from workers.info_gathering.pipeline import STAGES
    id_stage = next(s for s in STAGES if s.name == "identify_entry_points")
    agg_stage = next(s for s in STAGES if s.name == "aggregate_entry_points")
    assert id_stage.section_id == agg_stage.section_id == "4.1.6"


def test_new_tools_registered_as_light_in_concurrency():
    from workers.info_gathering.concurrency import TOOL_WEIGHTS
    assert TOOL_WEIGHTS["WebSocketProber"] == "LIGHT"
    assert TOOL_WEIGHTS["EntryPointAggregator"] == "LIGHT"
