"""Tests for ScopeManager.classify() — 3-tier scope classification."""

from lib_webbh.scope import ScopeManager, ScopeResult


class TestPatternClassification:
    def setup_method(self):
        self.sm = ScopeManager(
            in_scope=["*.example.com", "example.com", "10.0.0.0/8", "123.*.0.*"],
            out_of_scope=["staging.example.com", "example.com/api/v1/internal/*"],
        )

    def test_exact_domain_in_scope(self):
        result = self.sm.classify("example.com")
        assert result.classification == "in-scope"

    def test_wildcard_subdomain_in_scope(self):
        result = self.sm.classify("api.example.com")
        assert result.classification == "in-scope"

    def test_out_of_scope_takes_priority(self):
        result = self.sm.classify("staging.example.com")
        assert result.classification == "out-of-scope"

    def test_path_out_of_scope(self):
        result = self.sm.classify("example.com/api/v1/internal/secret")
        assert result.classification == "out-of-scope"

    def test_ip_cidr_in_scope(self):
        result = self.sm.classify("10.50.30.1")
        assert result.classification == "in-scope"

    def test_ip_octet_wildcard_in_scope(self):
        result = self.sm.classify("123.99.0.50")
        assert result.classification == "in-scope"

    def test_unknown_domain_is_pending(self):
        result = self.sm.classify("other.com")
        assert result.classification == "pending"

    def test_unknown_ip_is_pending(self):
        result = self.sm.classify("200.200.200.200")
        assert result.classification == "pending"

    def test_result_includes_matched_pattern(self):
        result = self.sm.classify("api.example.com")
        assert result.matched_pattern == "*.example.com"

    def test_result_matched_pattern_none_for_pending(self):
        result = self.sm.classify("other.com")
        assert result.matched_pattern is None

    def test_backwards_compat_is_in_scope_still_works(self):
        """Existing is_in_scope() API must still work with target_profile dict."""
        sm = ScopeManager(target_profile={
            "in_scope_domains": ["*.example.com"],
            "out_scope_domains": ["staging.example.com"],
        })
        result = sm.is_in_scope("api.example.com")
        assert result.in_scope is True

    def test_backwards_compat_out_of_scope(self):
        sm = ScopeManager(target_profile={
            "in_scope_domains": ["*.example.com"],
            "out_scope_domains": ["staging.example.com"],
        })
        result = sm.is_in_scope("staging.example.com")
        assert result.in_scope is False
