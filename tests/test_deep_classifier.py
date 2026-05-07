"""Tests for the 7-layer deep scope classifier."""

import pytest
from unittest.mock import AsyncMock, patch
from lib_webbh.deep_classifier import DeepClassifier


@pytest.fixture
def classifier():
    return DeepClassifier(
        in_scope_domains=["example.com", "*.example.com"],
        in_scope_ips=["10.0.0.0/8"],
    )


class TestDeepClassifier:
    @pytest.mark.anyio
    async def test_dns_resolution_associates_ip(self, classifier):
        """Layer 1: IP that reverse-resolves to in-scope domain -> associated."""
        with patch("lib_webbh.deep_classifier.reverse_dns",
                   new_callable=AsyncMock, return_value="lb1.example.com"), \
             patch("lib_webbh.deep_classifier.get_tls_sans",
                   new_callable=AsyncMock, return_value=[]), \
             patch("lib_webbh.deep_classifier.check_http_hosting",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.check_header_linkage",
                   new_callable=AsyncMock, return_value=None):
            result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
        assert result.classification == "associated"
        assert result.association_method == "dns_resolution"

    @pytest.mark.anyio
    async def test_tls_san_associates_ip(self, classifier):
        """Layer 2: IP with cert SAN matching in-scope domain -> associated."""
        with patch("lib_webbh.deep_classifier.reverse_dns",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.get_tls_sans",
                   new_callable=AsyncMock, return_value=["*.example.com", "example.com"]), \
             patch("lib_webbh.deep_classifier.check_http_hosting",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.check_header_linkage",
                   new_callable=AsyncMock, return_value=None):
            result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
        assert result.classification == "associated"
        assert result.association_method == "tls_san"

    @pytest.mark.anyio
    async def test_http_redirect_associates(self, classifier):
        """Layer 3: HTTP redirect to in-scope domain -> associated."""
        with patch("lib_webbh.deep_classifier.reverse_dns",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.get_tls_sans",
                   new_callable=AsyncMock, return_value=[]), \
             patch("lib_webbh.deep_classifier.check_http_hosting",
                   new_callable=AsyncMock, return_value="www.example.com"), \
             patch("lib_webbh.deep_classifier.check_header_linkage",
                   new_callable=AsyncMock, return_value=None):
            result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
        assert result.classification == "associated"
        assert result.association_method == "http_redirect"

    @pytest.mark.anyio
    async def test_header_linkage_associates(self, classifier):
        """Layer 5: Response headers reference in-scope domain -> associated."""
        with patch("lib_webbh.deep_classifier.reverse_dns",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.get_tls_sans",
                   new_callable=AsyncMock, return_value=[]), \
             patch("lib_webbh.deep_classifier.check_http_hosting",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.check_header_linkage",
                   new_callable=AsyncMock, return_value="api.example.com"):
            result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
        assert result.classification == "associated"
        assert result.association_method == "header_linkage"

    @pytest.mark.anyio
    async def test_all_layers_fail_returns_undetermined(self, classifier):
        """All layers fail -> undetermined."""
        with patch("lib_webbh.deep_classifier.reverse_dns",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.get_tls_sans",
                   new_callable=AsyncMock, return_value=[]), \
             patch("lib_webbh.deep_classifier.check_http_hosting",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.lookup_asn",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.check_header_linkage",
                   new_callable=AsyncMock, return_value=None):
            result = await classifier.classify_deep("200.200.200.200", asset_type="ip")
        assert result.classification == "undetermined"
        assert result.association_method is None

    @pytest.mark.anyio
    async def test_discovered_from_in_scope_associates(self, classifier):
        """Layer 7: Asset discovered from in-scope parent -> associated."""
        result = await classifier.classify_deep(
            "cdn.otherdomain.com", asset_type="domain",
            discovered_from_scope="in-scope",
        )
        assert result.classification == "associated"
        assert result.association_method == "discovered_from"

    @pytest.mark.anyio
    async def test_discovered_from_non_in_scope_continues(self, classifier):
        """Discovery from non-in-scope parent doesn't auto-associate."""
        with patch("lib_webbh.deep_classifier.reverse_dns",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.get_tls_sans",
                   new_callable=AsyncMock, return_value=[]), \
             patch("lib_webbh.deep_classifier.check_http_hosting",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.lookup_asn",
                   new_callable=AsyncMock, return_value=None), \
             patch("lib_webbh.deep_classifier.check_header_linkage",
                   new_callable=AsyncMock, return_value=None):
            result = await classifier.classify_deep(
                "cdn.otherdomain.com", asset_type="domain",
                discovered_from_scope="pending",
            )
        assert result.classification == "undetermined"
