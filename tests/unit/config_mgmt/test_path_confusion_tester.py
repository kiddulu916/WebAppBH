"""Unit tests for PathConfusionTester pure helper functions (WSTG-CONF-13)."""
from workers.config_mgmt.tools.path_confusion_tester import (
    _is_cacheable,
    _analyze_confused_response,
)

# ── _is_cacheable ──────────────────────────────────────────────────────────────

def test_is_cacheable_no_header():
    assert _is_cacheable({}) is True


def test_is_cacheable_with_no_store():
    assert _is_cacheable({"cache-control": "no-store"}) is False


def test_is_cacheable_with_private():
    assert _is_cacheable({"cache-control": "private, max-age=3600"}) is False


def test_is_cacheable_with_no_cache():
    assert _is_cacheable({"cache-control": "no-cache"}) is False


def test_is_cacheable_with_max_age_only():
    assert _is_cacheable({"cache-control": "max-age=3600"}) is True


def test_is_cacheable_case_insensitive():
    assert _is_cacheable({"cache-control": "NO-STORE"}) is False


# ── _analyze_confused_response ─────────────────────────────────────────────────

_BASELINE = "sensitive dashboard content for user john, session data here"
_SIMILAR  = "sensitive dashboard content for user john, session data here csrf=abc"
_DIFFERENT = "404 Not Found — the page you requested does not exist on this server"

def test_analyze_high_severity_cacheable():
    result = _analyze_confused_response(
        "https://example.com/dashboard",
        "https://example.com/dashboard/x.js",
        _BASELINE,
        _SIMILAR,
        {"cache-control": "max-age=3600"},
    )
    assert result is not None
    vuln = result["vulnerability"]
    assert vuln["severity"] == "high"
    assert vuln["section_id"] == "WSTG-CONF-13"
    assert vuln["section_id"] == "WSTG-CONF-13"
    assert "x.js" in vuln["location"]


def test_analyze_medium_severity_no_store():
    result = _analyze_confused_response(
        "https://example.com/dashboard",
        "https://example.com/dashboard/x.js",
        _BASELINE,
        _SIMILAR,
        {"cache-control": "no-store"},
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "medium"


def test_analyze_medium_severity_no_cache():
    result = _analyze_confused_response(
        "https://example.com/dashboard",
        "https://example.com/dashboard/x.js",
        _BASELINE,
        _SIMILAR,
        {"cache-control": "no-cache, no-store"},
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "medium"


def test_analyze_no_finding_when_different():
    result = _analyze_confused_response(
        "https://example.com/dashboard",
        "https://example.com/dashboard/x.js",
        _BASELINE,
        _DIFFERENT,
        {},
    )
    assert result is None


def test_analyze_no_finding_on_empty_confused_body():
    result = _analyze_confused_response(
        "https://example.com/dashboard",
        "https://example.com/dashboard/x.js",
        _BASELINE,
        "",
        {},
    )
    assert result is None


def test_analyze_name_contains_confused_url():
    result = _analyze_confused_response(
        "https://example.com/account",
        "https://example.com/account/x.png",
        _BASELINE,
        _SIMILAR,
        {},
    )
    assert result is not None
    assert "https://example.com/account/x.png" in result["vulnerability"]["name"]
