"""Unit tests for HttpSecurityHeadersTester pure helper functions (WSTG-CONF-14)."""
from workers.config_mgmt.tools.http_security_headers_tester import (
    _classify_static_headers,
    _classify_cors,
)


# ── _classify_static_headers ───────────────────────────────────────────────────

def test_static_missing_xfo_is_low():
    results = _classify_static_headers("example.com", {})
    names = [r["vulnerability"]["name"] for r in results if "vulnerability" in r]
    assert any("X-Frame-Options" in n for n in names)
    xfo = next(r for r in results if "X-Frame-Options" in r["vulnerability"]["name"])
    assert xfo["vulnerability"]["severity"] == "low"
    assert xfo["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_xfo_allow_from_is_low():
    headers = {"x-frame-options": "ALLOW-FROM https://trusted.com"}
    results = _classify_static_headers("example.com", headers)
    xfo = next(
        (r for r in results if "X-Frame-Options" in r["vulnerability"]["name"]), None
    )
    assert xfo is not None
    assert xfo["vulnerability"]["severity"] == "low"
    assert xfo["vulnerability"]["section_id"] == "WSTG-CONF-14"
    assert "deprecated" in xfo["vulnerability"]["name"].lower() or \
           "allow-from" in xfo["vulnerability"]["description"].lower()


def test_static_xfo_sameorigin_no_finding():
    headers = {
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-permitted-cross-domain-policies": "none",
    }
    results = _classify_static_headers("example.com", headers)
    xfo_findings = [r for r in results if "X-Frame-Options" in r.get("vulnerability", {}).get("name", "")]
    assert xfo_findings == []


def test_static_missing_xcto_is_low():
    results = _classify_static_headers("example.com", {})
    xcto = next(
        (r for r in results if "X-Content-Type-Options" in r["vulnerability"]["name"]), None
    )
    assert xcto is not None
    assert xcto["vulnerability"]["severity"] == "low"


def test_static_xcto_nosniff_no_finding():
    headers = {
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-permitted-cross-domain-policies": "none",
    }
    results = _classify_static_headers("example.com", headers)
    xcto_findings = [r for r in results if "X-Content-Type-Options" in r.get("vulnerability", {}).get("name", "")]
    assert xcto_findings == []


def test_static_xcto_wrong_value_is_medium():
    headers = {"x-content-type-options": "sniff"}
    results = _classify_static_headers("example.com", headers)
    xcto = next(
        (r for r in results if "X-Content-Type-Options" in r["vulnerability"]["name"]), None
    )
    assert xcto is not None
    assert xcto["vulnerability"]["severity"] == "medium"
    assert xcto["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_xcto_empty_is_medium():
    headers = {"x-content-type-options": ""}
    results = _classify_static_headers("example.com", headers)
    xcto = next(
        (r for r in results if "X-Content-Type-Options" in r["vulnerability"]["name"]), None
    )
    assert xcto is not None
    assert xcto["vulnerability"]["severity"] == "medium"
    assert xcto["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_missing_referrer_policy_is_info():
    results = _classify_static_headers("example.com", {})
    rp = next(
        (r for r in results if "Referrer-Policy" in r["vulnerability"]["name"]), None
    )
    assert rp is not None
    assert rp["vulnerability"]["severity"] == "info"


def test_static_referrer_policy_unsafe_url_is_medium():
    headers = {"referrer-policy": "unsafe-url"}
    results = _classify_static_headers("example.com", headers)
    rp = next(
        (r for r in results if "Referrer-Policy" in r["vulnerability"]["name"]), None
    )
    assert rp is not None
    assert rp["vulnerability"]["severity"] == "medium"
    assert rp["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_referrer_policy_no_referrer_no_finding():
    headers = {
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-permitted-cross-domain-policies": "none",
    }
    results = _classify_static_headers("example.com", headers)
    rp_findings = [r for r in results if "Referrer-Policy" in r.get("vulnerability", {}).get("name", "")]
    assert rp_findings == []


def test_static_missing_permissions_policy_is_info():
    results = _classify_static_headers("example.com", {})
    pp = next(
        (r for r in results if "Permissions-Policy" in r["vulnerability"]["name"]), None
    )
    assert pp is not None
    assert pp["vulnerability"]["severity"] == "info"


def test_static_permissions_policy_empty_is_low():
    headers = {"permissions-policy": ""}
    results = _classify_static_headers("example.com", headers)
    pp = next(
        (r for r in results if "Permissions-Policy" in r["vulnerability"]["name"]), None
    )
    assert pp is not None
    assert pp["vulnerability"]["severity"] == "low"
    assert pp["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_permissions_policy_non_empty_no_finding():
    headers = {
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-permitted-cross-domain-policies": "none",
    }
    results = _classify_static_headers("example.com", headers)
    pp_findings = [r for r in results if "Permissions-Policy" in r.get("vulnerability", {}).get("name", "")]
    assert pp_findings == []


def test_static_missing_xpcdp_is_info():
    results = _classify_static_headers("example.com", {})
    xpcdp = next(
        (r for r in results if "X-Permitted-Cross-Domain-Policies" in r["vulnerability"]["name"]), None
    )
    assert xpcdp is not None
    assert xpcdp["vulnerability"]["severity"] == "info"


def test_static_xpcdp_all_is_medium():
    headers = {"x-permitted-cross-domain-policies": "all"}
    results = _classify_static_headers("example.com", headers)
    xpcdp = next(
        (r for r in results if "X-Permitted-Cross-Domain-Policies" in r["vulnerability"]["name"]), None
    )
    assert xpcdp is not None
    assert xpcdp["vulnerability"]["severity"] == "medium"
    assert xpcdp["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_xpcdp_master_only_is_medium():
    headers = {"x-permitted-cross-domain-policies": "master-only"}
    results = _classify_static_headers("example.com", headers)
    xpcdp = next(
        (r for r in results if "X-Permitted-Cross-Domain-Policies" in r["vulnerability"]["name"]), None
    )
    assert xpcdp is not None
    assert xpcdp["vulnerability"]["severity"] == "medium"
    assert xpcdp["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_static_xpcdp_none_no_finding():
    headers = {
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-permitted-cross-domain-policies": "none",
    }
    results = _classify_static_headers("example.com", headers)
    xpcdp_findings = [r for r in results if "X-Permitted-Cross-Domain-Policies" in r.get("vulnerability", {}).get("name", "")]
    assert xpcdp_findings == []


def test_static_all_headers_correct_returns_empty():
    headers = {
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
        "x-permitted-cross-domain-policies": "none",
    }
    assert _classify_static_headers("example.com", headers) == []


def test_static_section_id_is_conf14():
    results = _classify_static_headers("example.com", {})
    for r in results:
        assert r["vulnerability"]["section_id"] == "WSTG-CONF-14"


# ── _classify_cors ─────────────────────────────────────────────────────────────

def test_cors_wildcard_alone_is_medium():
    headers = {"access-control-allow-origin": "*"}
    results = _classify_cors("https://example.com/api", headers)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "medium"
    assert results[0]["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_cors_wildcard_with_credentials_true_is_high():
    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    }
    results = _classify_cors("https://example.com/api", headers)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "high"
    assert results[0]["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_cors_wildcard_with_credentials_false_is_medium():
    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "false",
    }
    results = _classify_cors("https://example.com/api", headers)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "medium"
    assert results[0]["vulnerability"]["section_id"] == "WSTG-CONF-14"


def test_cors_specific_origin_no_finding():
    headers = {"access-control-allow-origin": "https://trusted.example.com"}
    assert _classify_cors("https://example.com/api", headers) == []


def test_cors_no_acao_header_no_finding():
    assert _classify_cors("https://example.com/api", {}) == []


def test_cors_finding_contains_url():
    headers = {"access-control-allow-origin": "*"}
    results = _classify_cors("https://example.com/api/users", headers)
    assert "https://example.com/api/users" in results[0]["vulnerability"]["location"]
