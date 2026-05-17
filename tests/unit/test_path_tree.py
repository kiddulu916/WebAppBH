# tests/unit/test_path_tree.py
import pytest
from lib_webbh.path_tree import PathTreeBuilder


class TestParseSegments:
    def test_simple_path(self):
        segments = PathTreeBuilder._parse_segments("https://example.com/admin/login")
        assert segments == [("/admin", "admin"), ("/admin/login", "login")]

    def test_root_only(self):
        segments = PathTreeBuilder._parse_segments("https://example.com/")
        assert segments == []

    def test_no_path(self):
        segments = PathTreeBuilder._parse_segments("https://example.com")
        assert segments == []

    def test_trailing_slash(self):
        segments = PathTreeBuilder._parse_segments("https://example.com/admin/")
        assert segments == [("/admin", "admin")]

    def test_deep_path(self):
        segments = PathTreeBuilder._parse_segments("https://t-mobile.com/accessory/jbl/item")
        assert segments == [
            ("/accessory", "accessory"),
            ("/accessory/jbl", "jbl"),
            ("/accessory/jbl/item", "item"),
        ]

    def test_invalid_url(self):
        segments = PathTreeBuilder._parse_segments("not-a-url")
        assert segments == []
