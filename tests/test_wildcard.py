"""Tests for the wildcard pattern matching engine."""

import pytest
from lib_webbh.wildcard import match_domain, match_ip, match_path, match_pattern


class TestDomainWildcards:
    def test_exact_match(self):
        assert match_domain("example.com", "example.com") is True

    def test_exact_no_match(self):
        assert match_domain("other.com", "example.com") is False

    def test_star_wildcard(self):
        assert match_domain("api.example.com", "*.example.com") is True

    def test_star_wildcard_no_match_base(self):
        assert match_domain("example.com", "*.example.com") is False

    def test_star_wildcard_nested_subdomain(self):
        assert match_domain("a.b.example.com", "*.example.com") is True

    def test_doublestar_alias(self):
        assert match_domain("api.example.com", "**.example.com") is True

    def test_doublestar_nested(self):
        assert match_domain("a.b.c.example.com", "**.example.com") is True

    def test_case_insensitive(self):
        assert match_domain("API.Example.COM", "*.example.com") is True


class TestIPWildcards:
    def test_exact_ip(self):
        assert match_ip("10.0.0.1", "10.0.0.1") is True

    def test_exact_ip_no_match(self):
        assert match_ip("10.0.0.2", "10.0.0.1") is False

    def test_cidr(self):
        assert match_ip("192.168.1.50", "192.168.0.0/16") is True

    def test_cidr_no_match(self):
        assert match_ip("10.0.0.1", "192.168.0.0/16") is False

    def test_single_octet_wildcard(self):
        assert match_ip("123.99.123.123", "123.*.123.123") is True

    def test_single_octet_wildcard_no_match(self):
        assert match_ip("124.99.123.123", "123.*.123.123") is False

    def test_multi_octet_wildcard(self):
        assert match_ip("123.123.50.60", "123.123.*.*") is True

    def test_first_two_octets_wildcard(self):
        assert match_ip("10.20.123.123", "*.*.123.123") is True

    def test_all_wildcards(self):
        assert match_ip("1.2.3.4", "*.*.*.*") is True

    def test_mixed_wildcards(self):
        assert match_ip("10.123.20.123", "*.123.*.123") is True

    def test_mixed_wildcards_no_match(self):
        assert match_ip("10.124.20.123", "*.123.*.123") is False

    def test_first_octet_wildcard(self):
        assert match_ip("99.0.0.1", "*.0.0.1") is True

    def test_last_three_wildcards(self):
        assert match_ip("123.1.2.3", "123.*.*.*") is True


class TestPathWildcards:
    def test_trailing_star(self):
        assert match_path("example.com/api/v1/users", "example.com/api/v1/*") is True

    def test_trailing_star_no_match_parent(self):
        assert match_path("example.com/api/v2/users", "example.com/api/v1/*") is False

    def test_extension_wildcard(self):
        assert match_path("example.com/api/v1/data.json", "example.com/api/v1/*.json") is True

    def test_extension_wildcard_wrong_ext(self):
        assert match_path("example.com/api/v1/data.xml", "example.com/api/v1/*.json") is False

    def test_filename_wildcard(self):
        assert match_path("example.com/api/v1/file.txt", "example.com/api/v1/file.*") is True

    def test_single_segment_wildcard(self):
        assert match_path("example.com/foo/config", "example.com/*/config") is True

    def test_globstar_any_domain(self):
        assert match_path("example.com/api/v1/foo", "**/api/v1/*") is True
        assert match_path("other.com/prefix/api/v1/bar", "**/api/v1/*") is True

    def test_globstar_recursive_path(self):
        assert match_path("example.com/a/secret", "example.com/**/secret") is True
        assert match_path("example.com/a/b/c/secret", "example.com/**/secret") is True
        assert match_path("example.com/secret", "example.com/**/secret") is True


class TestMatchPattern:
    """Top-level dispatcher that auto-detects pattern type."""

    def test_detects_domain_pattern(self):
        assert match_pattern("api.example.com", "*.example.com") is True

    def test_detects_ip_pattern(self):
        assert match_pattern("192.168.1.1", "192.168.0.0/16") is True

    def test_detects_ip_wildcard(self):
        assert match_pattern("10.0.0.1", "10.*.*.*") is True

    def test_detects_path_pattern(self):
        assert match_pattern("example.com/api/v1/foo", "example.com/api/v1/*") is True

    def test_detects_globstar(self):
        assert match_pattern("other.com/deep/api/v1/x", "**/api/v1/*") is True

    def test_out_of_scope_pattern(self):
        assert match_pattern("example.com/api/v1/admin", "example.com/api/v1/*") is True

    def test_no_match(self):
        assert match_pattern("other.com", "example.com") is False
