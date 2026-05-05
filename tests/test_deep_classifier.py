"""Tests for the async deep scope classifier (7-layer inference engine)."""

import pytest
from unittest.mock import AsyncMock, patch
from lib_webbh.deep_classifier import DeepClassifier


@pytest.fixture
def classifier():
    return DeepClassifier(
        in_scope_domains=["example.com", "*.example.com"],
        in_scope_ips=["10.0.0.0/8"],
    )


@pytest.mark.anyio
async def test_dns_resolution_associates_ip(classifier):
    """Layer 2: IP that reverse-resolves to in-scope domain -> associated."""
    with patch(
        "lib_webbh.deep_classifier.reverse_dns",
        new_callable=AsyncMock,
        return_value="lb1.example.com",
    ):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "associated"
    assert result.association_method == "dns_resolution"


@pytest.mark.anyio
async def test_tls_san_associates_ip(classifier):
    """Layer 3: IP with cert SAN matching in-scope domain -> associated."""
    with patch(
        "lib_webbh.deep_classifier.reverse_dns",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.get_tls_sans",
        new_callable=AsyncMock,
        return_value=["*.example.com", "example.com"],
    ):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "associated"
    assert result.association_method == "tls_san"


@pytest.mark.anyio
async def test_http_hosting_associates_ip(classifier):
    """Layer 4: IP serving content with in-scope domain in Host header -> associated."""
    with patch(
        "lib_webbh.deep_classifier.reverse_dns",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.get_tls_sans",
        new_callable=AsyncMock,
        return_value=[],
    ), patch(
        "lib_webbh.deep_classifier.check_http_hosting",
        new_callable=AsyncMock,
        return_value="example.com",
    ):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "associated"
    assert result.association_method == "http_hosting"


@pytest.mark.anyio
async def test_asn_associates_ip(classifier):
    """Layer 5: IP in same ASN as in-scope assets -> associated."""
    with patch(
        "lib_webbh.deep_classifier.reverse_dns",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.get_tls_sans",
        new_callable=AsyncMock,
        return_value=[],
    ), patch(
        "lib_webbh.deep_classifier.check_http_hosting",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.lookup_asn",
        new_callable=AsyncMock,
        return_value="AS12345-ExampleCorp",
    ):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "associated"
    assert result.association_method == "asn_match"


@pytest.mark.anyio
async def test_all_layers_fail_returns_undetermined(classifier):
    """All layers fail -> undetermined."""
    with patch(
        "lib_webbh.deep_classifier.reverse_dns",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.get_tls_sans",
        new_callable=AsyncMock,
        return_value=[],
    ), patch(
        "lib_webbh.deep_classifier.check_http_hosting",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.lookup_asn",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.check_header_linkage",
        new_callable=AsyncMock,
        return_value=None,
    ):
        result = await classifier.classify_deep("200.200.200.200", asset_type="ip")
    assert result.classification == "undetermined"
    assert result.association_method is None


@pytest.mark.anyio
async def test_discovered_from_associates(classifier):
    """Layer 7: Asset discovered from in-scope parent -> associated."""
    result = await classifier.classify_deep(
        "cdn.otherdomain.com",
        asset_type="domain",
        discovered_from_scope="in-scope",
    )
    assert result.classification == "associated"
    assert result.association_method == "discovered_from"


@pytest.mark.anyio
async def test_dns_resolution_domain_not_in_scope(classifier):
    """Reverse DNS returning unrelated domain does not associate."""
    with patch(
        "lib_webbh.deep_classifier.reverse_dns",
        new_callable=AsyncMock,
        return_value="unrelated.otherdomain.net",
    ), patch(
        "lib_webbh.deep_classifier.get_tls_sans",
        new_callable=AsyncMock,
        return_value=[],
    ), patch(
        "lib_webbh.deep_classifier.check_http_hosting",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.lookup_asn",
        new_callable=AsyncMock,
        return_value=None,
    ), patch(
        "lib_webbh.deep_classifier.check_header_linkage",
        new_callable=AsyncMock,
        return_value=None,
    ):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "undetermined"
