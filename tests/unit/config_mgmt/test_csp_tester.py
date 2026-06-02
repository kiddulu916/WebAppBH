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


import workers.config_mgmt.tools.csp_tester as csp_mod
from workers.config_mgmt.tools.csp_tester import _load_bypass_db


def test_load_bypass_db_reads_two_column_tsv(tmp_path, monkeypatch):
    tsv = tmp_path / "data.tsv"
    tsv.write_text(
        'ajax.googleapis.com\t<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>\n'
        'cdn.example.com\t<script src="https://cdn.example.com/x.js"></script>\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tsv))
    result = _load_bypass_db()
    assert len(result) == 2
    assert result[0] == ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>')
    assert result[1] == ("cdn.example.com", '<script src="https://cdn.example.com/x.js"></script>')


def test_load_bypass_db_domain_only_rows(tmp_path, monkeypatch):
    tsv = tmp_path / "data.tsv"
    tsv.write_text("example.com\nother.com\n", encoding="utf-8")
    monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tsv))
    result = _load_bypass_db()
    assert result == [("example.com", ""), ("other.com", "")]


def test_load_bypass_db_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tmp_path / "nonexistent.tsv"))
    result = _load_bypass_db()
    assert result == []


def test_load_bypass_db_lowercases_domain(tmp_path, monkeypatch):
    tsv = tmp_path / "data.tsv"
    tsv.write_text("AJAX.GoogleAPIs.COM\t<script src=\"https://AJAX.GoogleAPIs.COM/x.js\"></script>\n", encoding="utf-8")
    monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tsv))
    result = _load_bypass_db()
    assert result[0][0] == "ajax.googleapis.com"


from workers.config_mgmt.tools.csp_tester import _parse_csp_source


def test_parse_csp_source_bare_host():
    result = _parse_csp_source("ajax.googleapis.com")
    assert result == {
        "scheme": None,
        "host": "ajax.googleapis.com",
        "wildcard_subdomain": False,
        "path_prefix": None,
    }


def test_parse_csp_source_wildcard_subdomain():
    result = _parse_csp_source("*.googleapis.com")
    assert result == {
        "scheme": None,
        "host": "googleapis.com",
        "wildcard_subdomain": True,
        "path_prefix": None,
    }


def test_parse_csp_source_scheme_and_host():
    result = _parse_csp_source("https://cdn.example.com")
    assert result == {
        "scheme": "https",
        "host": "cdn.example.com",
        "wildcard_subdomain": False,
        "path_prefix": None,
    }


def test_parse_csp_source_scheme_host_and_path():
    result = _parse_csp_source("https://cdn.example.com/scripts/")
    assert result == {
        "scheme": "https",
        "host": "cdn.example.com",
        "wildcard_subdomain": False,
        "path_prefix": "/scripts/",
    }


def test_parse_csp_source_bare_wildcard():
    result = _parse_csp_source("*")
    assert result == {
        "scheme": None,
        "host": "*",
        "wildcard_subdomain": False,
        "path_prefix": None,
    }


def test_parse_csp_source_bare_scheme_returns_none():
    assert _parse_csp_source("https:") is None
    assert _parse_csp_source("data:") is None
    assert _parse_csp_source("blob:") is None


def test_parse_csp_source_strips_port():
    result = _parse_csp_source("cdn.example.com:8443")
    assert result["host"] == "cdn.example.com"


from workers.config_mgmt.tools.csp_tester import _matches_csp_source


def _src(host, *, scheme=None, wildcard_subdomain=False, path_prefix=None):
    """Helper to build a parsed CSP source dict."""
    return {
        "scheme": scheme,
        "host": host,
        "wildcard_subdomain": wildcard_subdomain,
        "path_prefix": path_prefix,
    }


def test_matches_csp_source_exact_host_match():
    gadget_code = '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>'
    assert _matches_csp_source("ajax.googleapis.com", gadget_code, _src("ajax.googleapis.com"))


def test_matches_csp_source_exact_host_no_match():
    gadget_code = '<script src="https://cdn.example.com/x.js"></script>'
    assert not _matches_csp_source("cdn.example.com", gadget_code, _src("ajax.googleapis.com"))


def test_matches_csp_source_wildcard_subdomain_matches():
    gadget_code = '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>'
    assert _matches_csp_source(
        "ajax.googleapis.com", gadget_code,
        _src("googleapis.com", wildcard_subdomain=True),
    )


def test_matches_csp_source_wildcard_subdomain_does_not_match_bare_domain():
    gadget_code = '<script src="https://googleapis.com/x.js"></script>'
    assert not _matches_csp_source(
        "googleapis.com", gadget_code,
        _src("googleapis.com", wildcard_subdomain=True),
    )


def test_matches_csp_source_global_wildcard_matches_anything():
    gadget_code = '<script src="https://anything.example.com/x.js"></script>'
    assert _matches_csp_source("anything.example.com", gadget_code, _src("*"))


def test_matches_csp_source_scheme_enforced_on_mismatch():
    gadget_code = '<script src="http://ajax.googleapis.com/x.js"></script>'
    assert not _matches_csp_source(
        "ajax.googleapis.com", gadget_code,
        _src("ajax.googleapis.com", scheme="https"),
    )


def test_matches_csp_source_scheme_not_enforced_when_absent():
    gadget_code = '<script src="http://ajax.googleapis.com/x.js"></script>'
    assert _matches_csp_source(
        "ajax.googleapis.com", gadget_code,
        _src("ajax.googleapis.com", scheme=None),
    )


def test_matches_csp_source_path_prefix_exact_match():
    gadget_code = '<script src="https://cdn.example.com/gtag/js"></script>'
    assert _matches_csp_source(
        "cdn.example.com", gadget_code,
        _src("cdn.example.com", path_prefix="/gtag/js"),
    )


def test_matches_csp_source_path_prefix_subpath_match():
    gadget_code = '<script src="https://cdn.example.com/gtag/js/file.js"></script>'
    assert _matches_csp_source(
        "cdn.example.com", gadget_code,
        _src("cdn.example.com", path_prefix="/gtag/js"),
    )


def test_matches_csp_source_path_prefix_segment_boundary_no_match():
    gadget_code = '<script src="https://cdn.example.com/gtag/jsloader"></script>'
    assert not _matches_csp_source(
        "cdn.example.com", gadget_code,
        _src("cdn.example.com", path_prefix="/gtag/js"),
    )


def test_matches_csp_source_fallback_url_when_no_src_attr():
    # No src= attribute in code — falls back to https://{domain}
    assert _matches_csp_source("example.com", "", _src("example.com"))


from workers.config_mgmt.tools.csp_tester import _match_csp_bypasses


def test_match_csp_bypasses_empty_csp_returns_empty(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [("ajax.googleapis.com", "")])
    assert _match_csp_bypasses("", "https://target.com/") == []


def test_match_csp_bypasses_empty_db_returns_empty(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [])
    results = _match_csp_bypasses(
        "script-src 'self' ajax.googleapis.com",
        "https://target.com/",
    )
    assert results == []


def test_match_csp_bypasses_finds_exact_domain(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
        ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>'),
        ("cdn.example.com", '<script src="https://cdn.example.com/x.js"></script>'),
    ])
    results = _match_csp_bypasses(
        "script-src 'self' ajax.googleapis.com",
        "https://target.com/",
    )
    assert len(results) == 1
    vuln = results[0]["vulnerability"]
    assert vuln["severity"] == "high"
    assert "ajax.googleapis.com" in vuln["name"]
    assert vuln["section_id"] == "WSTG-CONF-12"
    assert vuln["location"] == "https://target.com/"


def test_match_csp_bypasses_no_match_for_unknown_domain(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
        ("notinthepolicy.com", '<script src="https://notinthepolicy.com/x.js"></script>'),
    ])
    results = _match_csp_bypasses(
        "script-src 'self' ajax.googleapis.com",
        "https://target.com/",
    )
    assert results == []


def test_match_csp_bypasses_keywords_filtered_out(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
        ("self", ""),
        ("unsafe-inline", ""),
    ])
    results = _match_csp_bypasses(
        "script-src 'self' 'unsafe-inline'",
        "https://target.com/",
    )
    assert results == []


def test_match_csp_bypasses_nonce_filtered_out(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [("nonce-abc123", "")])
    results = _match_csp_bypasses(
        "script-src 'nonce-abc123'",
        "https://target.com/",
    )
    assert results == []


def test_match_csp_bypasses_wildcard_source_matches_subdomain(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
        ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/x.js"></script>'),
    ])
    results = _match_csp_bypasses(
        "script-src 'self' *.googleapis.com",
        "https://target.com/",
    )
    assert len(results) == 1
    assert "ajax.googleapis.com" in results[0]["vulnerability"]["name"]


def test_match_csp_bypasses_deduplicates_same_gadget(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
        ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/x.js"></script>'),
    ])
    # Two sources in the policy that both match the same gadget
    results = _match_csp_bypasses(
        "script-src ajax.googleapis.com *.googleapis.com",
        "https://target.com/",
    )
    assert len(results) == 1


def test_match_csp_bypasses_falls_back_to_default_src(monkeypatch):
    monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
        ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/x.js"></script>'),
    ])
    results = _match_csp_bypasses(
        "default-src 'self' ajax.googleapis.com",
        "https://target.com/",
    )
    assert len(results) == 1
