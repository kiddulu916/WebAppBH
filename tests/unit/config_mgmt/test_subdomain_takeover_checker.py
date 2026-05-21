"""Unit tests for SubdomainTakeoverChecker pure helpers (WSTG-CONF-10)."""
from workers.config_mgmt.tools.subdomain_takeover_checker import (
    _SECTION_ID,
    _build_subdomain_list,
    _parse_subjack_output,
    _classify_subjack_result,
    _parse_nuclei_output,
    _classify_nuclei_result,
)


# ── _build_subdomain_list ────────────────────────────────────────────────────

def test_build_subdomain_list_includes_wordlist():
    result = _build_subdomain_list([], "example.com")
    assert "www.example.com" in result
    assert "api.example.com" in result


def test_build_subdomain_list_includes_target_domain():
    result = _build_subdomain_list([], "example.com")
    assert "example.com" in result


def test_build_subdomain_list_strips_schemes():
    assets = ["https://api.example.com/v1/users?q=1"]
    result = _build_subdomain_list(assets, "example.com")
    assert "api.example.com" in result
    assert "https://api.example.com/v1/users?q=1" not in result


def test_build_subdomain_list_filters_out_of_scope():
    assets = ["https://other.com", "https://sub.example.com"]
    result = _build_subdomain_list(assets, "example.com")
    assert "other.com" not in result
    assert "sub.example.com" in result


def test_build_subdomain_list_deduplicates():
    # www.example.com comes from both DB and wordlist
    assets = ["https://www.example.com/page"]
    result = _build_subdomain_list(assets, "example.com")
    assert result.count("www.example.com") == 1


def test_build_subdomain_list_empty_db():
    result = _build_subdomain_list([], "example.com")
    assert len(result) > 0


# ── _parse_subjack_output ────────────────────────────────────────────────────

def test_parse_subjack_empty_string():
    assert _parse_subjack_output("") == []


def test_parse_subjack_empty_array():
    assert _parse_subjack_output("[]") == []


def test_parse_subjack_malformed_json():
    assert _parse_subjack_output("not json at all") == []


def test_parse_subjack_vulnerable_entry():
    raw = '[{"subdomain":"sub.example.com","service":"GitHub","vulnerable":true}]'
    result = _parse_subjack_output(raw)
    assert len(result) == 1
    assert result[0]["subdomain"] == "sub.example.com"
    assert result[0]["service"] == "GitHub"
    assert result[0]["vulnerable"] is True


def test_parse_subjack_non_vulnerable_entry():
    raw = '[{"subdomain":"blog.example.com","service":"Ghost","vulnerable":false}]'
    result = _parse_subjack_output(raw)
    assert len(result) == 1
    assert result[0]["vulnerable"] is False


def test_parse_subjack_multiple_entries():
    raw = '[{"subdomain":"a.example.com","service":"GitHub","vulnerable":true},{"subdomain":"b.example.com","service":"Heroku","vulnerable":false}]'
    result = _parse_subjack_output(raw)
    assert len(result) == 2


# ── _classify_subjack_result ─────────────────────────────────────────────────

def test_classify_subjack_vulnerable_is_critical():
    entry = {"subdomain": "sub.example.com", "service": "GitHub", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_subjack_dangling_is_high():
    entry = {"subdomain": "blog.example.com", "service": "Ghost", "vulnerable": False}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_subjack_section_id():
    entry = {"subdomain": "sub.example.com", "service": "GitHub", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-10"


def test_classify_subjack_has_location():
    entry = {"subdomain": "blog.example.com", "service": "Ghost", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["location"] == "blog.example.com"


def test_classify_subjack_name_includes_service():
    entry = {"subdomain": "sub.example.com", "service": "GitHub", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert "GitHub" in result["vulnerability"]["name"]


# ── _parse_nuclei_output ─────────────────────────────────────────────────────

def test_parse_nuclei_empty_output():
    assert _parse_nuclei_output("") == []


def test_parse_nuclei_single_line():
    line = '{"templateID":"github-takeover","host":"sub.example.com","matched-at":"http://sub.example.com","info":{"name":"GitHub Pages Takeover","severity":"high"},"type":"http"}'
    result = _parse_nuclei_output(line)
    assert len(result) == 1
    assert result[0]["template_id"] == "github-takeover"
    assert result[0]["host"] == "sub.example.com"
    assert result[0]["matched_at"] == "http://sub.example.com"
    assert result[0]["severity"] == "high"
    assert result[0]["name"] == "GitHub Pages Takeover"


def test_parse_nuclei_multi_line():
    lines = "\n".join([
        '{"templateID":"github-takeover","host":"a.example.com","matched-at":"http://a.example.com","info":{"name":"GitHub","severity":"high"},"type":"http"}',
        '{"templateID":"heroku-takeover","host":"b.example.com","matched-at":"http://b.example.com","info":{"name":"Heroku","severity":"high"},"type":"http"}',
    ])
    result = _parse_nuclei_output(lines)
    assert len(result) == 2


def test_parse_nuclei_malformed_line_skipped():
    text = "not json\n" + '{"templateID":"github-takeover","host":"sub.example.com","matched-at":"http://sub.example.com","info":{"name":"GitHub","severity":"high"},"type":"http"}'
    result = _parse_nuclei_output(text)
    assert len(result) == 1


def test_parse_nuclei_hyphen_template_id():
    # nuclei v3 uses "template-id" instead of "templateID"
    line = '{"template-id":"github-takeover","host":"sub.example.com","matched-at":"http://sub.example.com","info":{"name":"GitHub","severity":"high"},"type":"http"}'
    result = _parse_nuclei_output(line)
    assert len(result) == 1
    assert result[0]["template_id"] == "github-takeover"


# ── _classify_nuclei_result ──────────────────────────────────────────────────

def test_classify_nuclei_critical_severity():
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "critical", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_nuclei_high_maps_to_critical():
    # nuclei high = confirmed HTTP match = confirmed takeover
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "high", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_nuclei_medium_maps_to_high():
    entry = {"template_id": "some-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "medium", "name": "Some Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_nuclei_section_id():
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "high", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-10"


def test_classify_nuclei_location_is_matched_at():
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com/", "severity": "high", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["location"] == "http://sub.example.com/"


# ── _SECTION_ID constant ─────────────────────────────────────────────────────

def test_section_id_constant():
    assert _SECTION_ID == "WSTG-CONF-10"
