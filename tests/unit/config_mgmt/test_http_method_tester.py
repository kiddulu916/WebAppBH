"""Unit tests for HttpMethodTester pure helper functions (WSTG-CONF-06)."""
import pytest

from workers.config_mgmt.tools.http_method_tester import (
    _classify_method_response,
    _classify_cors,
    _is_dangerous_method,
    _build_probe_urls,
    _parse_allow_header,
    _SECTION_ID,
)


def test_classify_method_response_put_200_is_high():
    severity, _ = _classify_method_response("PUT", 200)
    assert severity == "high"


def test_classify_method_response_patch_201_is_high():
    severity, _ = _classify_method_response("PATCH", 201)
    assert severity == "high"


def test_classify_method_response_delete_405_is_none():
    severity, _ = _classify_method_response("DELETE", 405)
    assert severity is None


def test_classify_method_response_trace_200_is_medium():
    severity, _ = _classify_method_response("TRACE", 200)
    assert severity == "medium"


def test_classify_method_response_track_200_is_medium():
    severity, _ = _classify_method_response("TRACK", 200)
    assert severity == "medium"


def test_classify_method_response_put_403_is_none():
    severity, _ = _classify_method_response("PUT", 403)
    assert severity is None


def test_classify_cors_reflection_is_high():
    severity, vuln_type = _classify_cors(
        "https://evil.example.com",
        "https://evil.example.com",
        "",
    )
    assert severity == "high"
    assert vuln_type == "cors_origin_reflection"


def test_classify_cors_wildcard_with_creds_is_high():
    severity, vuln_type = _classify_cors(
        "https://evil.example.com",
        "*",
        "true",
    )
    assert severity == "high"
    assert vuln_type == "cors_wildcard_with_credentials"


def test_classify_cors_creds_only_is_medium():
    severity, vuln_type = _classify_cors(
        "https://evil.example.com",
        "https://same.com",
        "true",
    )
    assert severity == "medium"
    assert vuln_type == "cors_credentials_without_strict_origin"


def test_classify_cors_safe_is_none():
    severity, _ = _classify_cors(
        "https://evil.example.com",
        "https://same.com",
        "",
    )
    assert severity is None


def test_is_dangerous_method_true():
    for method in ("PUT", "DELETE", "PATCH", "PROPFIND", "COPY", "MOVE", "MKCOL", "LOCK", "UNLOCK"):
        assert _is_dangerous_method(method) is True, f"Expected {method} to be dangerous"


def test_is_dangerous_method_false():
    for method in ("GET", "POST", "HEAD"):
        assert _is_dangerous_method(method) is False, f"Expected {method} to be safe"


def test_build_probe_urls_uses_db_when_non_empty():
    db_urls = ["https://example.com/api", "https://example.com/v1"]
    result = _build_probe_urls("https://example.com", db_urls)
    assert result == db_urls


def test_build_probe_urls_fallback_when_db_empty():
    result = _build_probe_urls("https://example.com", [])
    assert len(result) > 0
    assert all(r.startswith("https://example.com") for r in result)


def test_parse_allow_header_splits_methods():
    result = _parse_allow_header("GET, POST, PUT")
    assert result == ["GET", "POST", "PUT"]


def test_parse_allow_header_empty_string():
    result = _parse_allow_header("")
    assert result == []


def test_section_id_is_wstg_conf_06():
    assert _SECTION_ID == "WSTG-CONF-06"
