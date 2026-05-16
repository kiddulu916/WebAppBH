"""Pipeline and concurrency registration tests for WSTG-INFO-06."""


def test_asset_types_includes_websocket_and_url():
    from lib_webbh.database import ASSET_TYPES
    assert "websocket" in ASSET_TYPES, "websocket missing from ASSET_TYPES"
    assert "url" in ASSET_TYPES, "url missing from ASSET_TYPES"
