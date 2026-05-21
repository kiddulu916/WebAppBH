"""Unit tests for CspTester pure helper functions (WSTG-CONF-12)."""
from workers.config_mgmt.tools.csp_tester import (
    _parse_csp_header,
    _classify_directives,
    _scan_meta_tag,
)


def test_parse_csp_header_basic():
    policy = _parse_csp_header("default-src 'self'; script-src 'self' https://cdn.example.com")
    assert policy == {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.example.com"],
    }


def test_parse_csp_header_empty():
    assert _parse_csp_header("") == {}
    assert _parse_csp_header(None) == {}


def test_classify_directives_missing_csp():
    results = _classify_directives("example.com", "https://example.com/", {})
    assert len(results) == 1
    vuln = results[0]["vulnerability"]
    assert vuln["severity"] == "high"
    assert "Missing" in vuln["name"]


def test_classify_directives_unsafe_inline_script():
    policy = {"default-src": ["'self'"], "script-src": ["'self'", "'unsafe-inline'"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("unsafe-inline" in v["name"] for v in vulns)
    assert any(v["severity"] == "high" for v in vulns)


def test_classify_directives_unsafe_eval():
    policy = {"default-src": ["'self'"], "script-src": ["'self'", "'unsafe-eval'"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("unsafe-eval" in v["name"] for v in vulns)
    assert any(v["severity"] == "high" for v in vulns)


def test_classify_directives_wildcard_script():
    policy = {"default-src": ["'self'"], "script-src": ["*"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("wildcard" in v["name"].lower() for v in vulns)
    assert any(v["severity"] == "high" for v in vulns)


def test_classify_directives_http_scheme():
    policy = {"default-src": ["'self'"], "script-src": ["'self'", "http:"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("insecure" in v["name"].lower() for v in vulns)
    assert any(v["severity"] == "high" for v in vulns)


def test_classify_directives_missing_default_src():
    policy = {"script-src": ["'self'"], "style-src": ["'self'"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("default-src" in v["name"] for v in vulns)
    severities = {v["severity"] for v in vulns}
    assert "medium" in severities
    assert "high" not in severities
    assert not any("object-src" in v["name"] for v in vulns), "object-src should not fire when default-src is also missing"


def test_classify_directives_compliant():
    policy = {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "object-src": ["'none'"],
        "img-src": ["'self'"],
        "font-src": ["'self'"],
    }
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r for r in results if "vulnerability" in r]
    observations = [r for r in results if "observation" in r]
    assert vulns == []
    assert len(observations) == 1
    assert observations[0]["observation"]["value"] == "compliant"


def test_scan_meta_tag_present():
    html = (
        '<html><head>'
        '<meta http-equiv="Content-Security-Policy"'
        ' content="default-src \'self\'; script-src \'unsafe-inline\'">'
        '</head><body></body></html>'
    )
    results = _scan_meta_tag("example.com", "https://example.com/", html)
    assert len(results) > 0
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("meta tag" in v["name"].lower() for v in vulns)
    severities = {v["severity"] for v in vulns}
    assert "low" in severities   # meta tag delivery finding
    assert "high" in severities  # unsafe-inline directive finding


def test_scan_meta_tag_absent():
    html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
    assert _scan_meta_tag("example.com", "https://example.com/", html) == []


def test_classify_directives_missing_object_src_with_default_src():
    """object-src finding fires when default-src is present but object-src is absent."""
    policy = {"default-src": ["'self'"], "script-src": ["'self'"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("object-src" in v["name"] for v in vulns)
    assert any(v["severity"] == "medium" for v in vulns)


def test_classify_directives_both_insecure_schemes():
    """Both http: and data: in script-src each produce a separate finding."""
    policy = {"default-src": ["'self'"], "script-src": ["'self'", "http:", "data:"]}
    results = _classify_directives("example.com", "https://example.com/", policy)
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    insecure = [v for v in vulns if "insecure" in v["name"].lower()]
    assert len(insecure) == 2, f"Expected 2 insecure-scheme findings, got {len(insecure)}: {[v['description'] for v in insecure]}"
    descriptions = {v["description"] for v in insecure}
    assert any("http:" in d for d in descriptions)
    assert any("data:" in d for d in descriptions)


def test_scan_meta_tag_multiline():
    html = (
        '<html><head>'
        '<meta http-equiv="Content-Security-Policy"\n'
        '      content="default-src \'self\'">'
        '</head></html>'
    )
    results = _scan_meta_tag("example.com", "https://example.com/", html)
    assert len(results) > 0
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("meta tag" in v["name"].lower() for v in vulns)


def test_scan_meta_tag_single_quoted_content():
    html = "<html><head><meta http-equiv='Content-Security-Policy' content='default-src \"self\"'></head></html>"
    results = _scan_meta_tag("example.com", "https://example.com/", html)
    assert len(results) > 0
    vulns = [r["vulnerability"] for r in results if "vulnerability" in r]
    assert any("meta tag" in v["name"].lower() for v in vulns)
