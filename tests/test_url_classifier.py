"""Tests for URL classification into canonical asset types."""

import pytest
from workers.info_gathering.tools.url_classifier import (
    classify_url,
    DORK_CATEGORY_MAP,
)


class TestClassifyUrl:
    """classify_url maps URL patterns to asset types."""

    @pytest.mark.parametrize("url,expected", [
        ("https://example.com/.env", "sensitive_file"),
        ("https://example.com/backup.sql", "sensitive_file"),
        ("https://example.com/config.bak", "sensitive_file"),
        ("https://example.com/dump.tar.gz", "sensitive_file"),
        ("https://example.com/report.pdf", "sensitive_file"),
        ("https://example.com/data.csv", "sensitive_file"),
        ("https://example.com/secrets.yml", "sensitive_file"),
        ("https://example.com/app.properties", "sensitive_file"),
    ])
    def test_sensitive_file_by_extension(self, url, expected):
        assert classify_url(url) == expected

    @pytest.mark.parametrize("url,expected", [
        ("https://example.com/admin/panel", "directory"),
        ("https://example.com/administrator/", "directory"),
        ("https://example.com/cpanel/login", "directory"),
        ("https://example.com/wp-admin/edit.php", "directory"),
        ("https://example.com/.git/config", "directory"),
        ("https://example.com/.svn/entries", "directory"),
    ])
    def test_directory_by_path(self, url, expected):
        assert classify_url(url) == expected

    @pytest.mark.parametrize("url", [
        "https://example.com/error/500",
        "https://example.com/debug-info",
        "https://example.com/traceback",
    ])
    def test_error_pages(self, url):
        assert classify_url(url) == "error"

    def test_plain_url_is_undetermined(self):
        assert classify_url("https://example.com/about") == "undetermined"
        assert classify_url("https://example.com/products/123") == "undetermined"

    def test_extension_takes_priority(self):
        # .env in path is sensitive_file even if it matches directory keyword
        assert classify_url("https://example.com/.env") == "sensitive_file"


class TestDorkCategoryMap:
    """DORK_CATEGORY_MAP covers all dork_patterns categories."""

    def test_all_categories_mapped(self):
        from workers.info_gathering.tools.dork_patterns import DORK_CATEGORIES
        for cat in DORK_CATEGORIES:
            assert cat in DORK_CATEGORY_MAP, f"Missing mapping for category: {cat}"

    def test_maps_to_valid_asset_types(self):
        from lib_webbh.database import ASSET_TYPES
        for cat, asset_type in DORK_CATEGORY_MAP.items():
            assert asset_type in ASSET_TYPES, f"{cat} maps to unknown type: {asset_type}"
