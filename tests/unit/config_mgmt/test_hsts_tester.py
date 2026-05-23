"""Unit tests for HstsTester pure helper functions (WSTG-CONF-07)."""
from workers.config_mgmt.tools.hsts_tester import (
    _SECTION_ID,
    _parse_hsts_header,
    _classify_hsts,
    _classify_http_redirect,
    _hsts_on_http,
)


def test_parse_hsts_header_full():
    result = _parse_hsts_header("max-age=31536000; includeSubDomains; preload")
    assert result["max_age"] == 31536000
    assert result["include_subdomains"] is True
    assert result["preload"] is True


def test_parse_hsts_header_max_age_only():
    result = _parse_hsts_header("max-age=3600")
    assert result["max_age"] == 3600
    assert result["include_subdomains"] is False
    assert result["preload"] is False


def test_classify_hsts_missing_header():
    results = _classify_hsts("example.com", "")
    vulns = [r for r in results if "vulnerability" in r]
    assert any(v["vulnerability"]["severity"] == "medium" for v in vulns)


def test_classify_hsts_max_age_too_short():
    results = _classify_hsts("example.com", "max-age=3600; includeSubDomains")
    vulns = [r for r in results if "vulnerability" in r]
    assert any("max-age" in v["vulnerability"]["name"].lower() for v in vulns)
    assert any(v["vulnerability"]["severity"] == "low" for v in vulns)


def test_classify_hsts_missing_include_subdomains():
    results = _classify_hsts("example.com", "max-age=31536000")
    vulns = [r for r in results if "vulnerability" in r]
    assert any("includeSubDomains" in v["vulnerability"]["name"] for v in vulns)
    assert any(v["vulnerability"]["severity"] == "low" for v in vulns)


def test_classify_hsts_no_preload_is_info_vuln():
    results = _classify_hsts("example.com", "max-age=31536000; includeSubDomains")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 1
    assert vulns[0]["vulnerability"]["severity"] == "info"
    assert "preload" in vulns[0]["vulnerability"]["name"].lower()
    assert not any("observation" in r for r in results)


def test_classify_hsts_compliant_returns_empty():
    results = _classify_hsts("example.com", "max-age=31536000; includeSubDomains; preload")
    assert results == []


def test_classify_hsts_section_id():
    results = _classify_hsts("example.com", "")
    vulns = [r for r in results if "vulnerability" in r]
    assert all(v["vulnerability"]["section_id"] == "WSTG-CONF-07" for v in vulns)


def test_classify_http_redirect_200_is_high():
    result = _classify_http_redirect("example.com", 200, None)
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"


def test_classify_http_redirect_to_http_is_high():
    result = _classify_http_redirect("example.com", 301, "http://example.com/")
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"


def test_classify_http_redirect_to_https_returns_none():
    result = _classify_http_redirect("example.com", 301, "https://example.com/")
    assert result is None


def test_classify_http_redirect_section_id():
    result = _classify_http_redirect("example.com", 200, None)
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-07"


def test_hsts_on_http_present_is_low():
    result = _hsts_on_http("example.com", "max-age=31536000")
    assert result is not None
    assert result["vulnerability"]["severity"] == "low"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-07"


def test_hsts_on_http_absent_is_none():
    result = _hsts_on_http("example.com", "")
    assert result is None


def test_section_id_constant():
    assert _SECTION_ID == "WSTG-CONF-07"


def test_classify_http_redirect_non_redirect_is_info_vuln():
    result = _classify_http_redirect("example.com", 404, None)
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "info"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-07"
