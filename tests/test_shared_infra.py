"""Test shared infrastructure fingerprinting."""
import pytest
from lib_webbh.shared_infra import is_shared_infra, InfraClassification


def test_cloudflare_cdn():
    result = is_shared_infra("cdn.cloudflare.com")
    assert result.is_shared is True
    assert result.provider == "Cloudflare"
    assert result.category == "CDN"


def test_amazonaws_s3():
    result = is_shared_infra("my-bucket.s3.amazonaws.com")
    assert result.is_shared is True
    assert result.provider == "AWS"


def test_custom_domain_not_shared():
    result = is_shared_infra("app.customdomain.com")
    assert result.is_shared is False


def test_known_saas_domain():
    result = is_shared_infra("company.zendesk.com")
    assert result.is_shared is True
    assert result.category == "SaaS"


def test_ip_in_cloud_cidr():
    result = is_shared_infra("104.16.0.1")
    assert result.is_shared is True
