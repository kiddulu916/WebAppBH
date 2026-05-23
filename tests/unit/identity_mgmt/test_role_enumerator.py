"""Unit tests for RoleEnumerator (WSTG-IDNT-01)."""
import json

import pytest

from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator


@pytest.fixture
def tool():
    return RoleEnumerator()


class FakeTarget:
    target_value = "example.com"


# ── parse_output ──────────────────────────────────────────────────────────────

def test_parse_output_valid_findings(tool):
    findings = [{"title": "Role found", "description": "x", "severity": "medium", "data": {}}]
    assert tool.parse_output(json.dumps(findings)) == findings


def test_parse_output_empty_list(tool):
    assert tool.parse_output("[]") == []


def test_parse_output_malformed_json_returns_empty(tool):
    assert tool.parse_output("not json {{{{") == []


def test_parse_output_empty_string_returns_empty(tool):
    assert tool.parse_output("") == []


def test_parse_output_whitespace_returns_empty(tool):
    assert tool.parse_output("   \n  ") == []


def test_parse_output_preserves_all_severity_levels(tool):
    findings = [
        {"title": "A", "severity": "info", "description": "", "data": {}},
        {"title": "B", "severity": "medium", "description": "", "data": {}},
        {"title": "C", "severity": "high", "description": "", "data": {}},
    ]
    result = tool.parse_output(json.dumps(findings))
    severities = [r["severity"] for r in result]
    assert severities == ["info", "medium", "high"]


# ── build_command basics ──────────────────────────────────────────────────────

def test_build_command_returns_python3(tool):
    cmd = tool.build_command(FakeTarget())
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    assert isinstance(cmd[2], str)


def test_build_command_script_is_valid_python(tool):
    script = tool.build_command(FakeTarget())[2]
    compile(script, "<string>", "exec")  # SyntaxError if invalid


def test_build_command_embeds_base_url_https(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "https://example.com" in script


def test_build_command_preserves_http_scheme(tool):
    class HttpTarget:
        target_value = "http://example.com"
    script = tool.build_command(HttpTarget())[2]
    assert "http://example.com" in script


# ── credentials serialization (bug fix) ───────────────────────────────────────

def test_build_command_none_credentials_serialized(tool):
    script = tool.build_command(FakeTarget(), credentials=None)[2]
    assert "credentials = None" in script


def test_build_command_dict_credentials_serialized(tool):
    script = tool.build_command(FakeTarget(), credentials={"token": "tok123"})[2]
    assert 'credentials = {"token": "tok123"}' in script


# ── Block 5: JS source scan ───────────────────────────────────────────────────

def test_build_command_script_contains_js_scan(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "script_srcs" in script
    assert "js_role_patterns" in script
    assert "isAdmin" in script
    assert "ROLE_ADMIN" in script


def test_build_command_js_scan_script_valid_python(tool):
    script = tool.build_command(FakeTarget())[2]
    compile(script, "<string>", "exec")


def test_build_command_js_url_resolution_handles_absolute(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "startswith" in script and "http" in script


# ── Block 6: Cookie/header role fuzzing ───────────────────────────────────────

def test_build_command_script_contains_cookie_fuzzing(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "inject_cookies" in script
    assert "inject_header_sets" in script
    assert "X-Role" in script


def test_build_command_cookie_fuzz_checks_status_drop(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "baseline_status" in script
    assert "status_drop" in script


def test_build_command_cookie_fuzz_script_valid_python(tool):
    script = tool.build_command(FakeTarget())[2]
    compile(script, "<string>", "exec")


# ── Block 7: Well-known accounts and role switching ───────────────────────────

def test_build_command_script_contains_wellknown_accounts(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "known_creds" in script
    assert "login_candidates" in script
    assert '"admin", "admin"' in script or "('admin', 'admin')" in script


def test_build_command_script_probes_login_endpoint(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "/api/login" in script
    assert "login_ep" in script


def test_build_command_script_uses_serialized_credentials_for_role_switch(tool):
    script = tool.build_command(FakeTarget(), credentials={"token": "xyz"})[2]
    assert "switch_paths" in script
    assert "xyz" in script


def test_build_command_wellknown_script_valid_python(tool):
    script = tool.build_command(FakeTarget(), credentials={"token": "abc"})[2]
    compile(script, "<string>", "exec")
