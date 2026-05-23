"""Unit tests for RegistrationTester (WSTG-IDNT-02)."""
import json
import pytest
from workers.identity_mgmt.tools.registration_tester import RegistrationTester


@pytest.fixture
def tool():
    return RegistrationTester()


class FakeTarget:
    target_value = "example.com"


class HttpTarget:
    target_value = "http://example.com"


# ── parse_output ──────────────────────────────────────────────────────────────

def test_parse_output_valid_findings(tool):
    findings = [{"title": "x", "description": "y", "severity": "medium", "data": {}}]
    assert tool.parse_output(json.dumps(findings)) == findings


def test_parse_output_empty_list(tool):
    assert tool.parse_output("[]") == []


def test_parse_output_malformed_json_returns_empty(tool):
    assert tool.parse_output("not json") == []


def test_parse_output_empty_string_returns_empty(tool):
    assert tool.parse_output("") == []


def test_parse_output_whitespace_returns_empty(tool):
    assert tool.parse_output("   \n  ") == []


def test_parse_output_preserves_all_severity_levels(tool):
    findings = [
        {"title": "A", "severity": "info", "description": "", "data": {}},
        {"title": "B", "severity": "low", "description": "", "data": {}},
        {"title": "C", "severity": "medium", "description": "", "data": {}},
        {"title": "D", "severity": "high", "description": "", "data": {}},
    ]
    assert [r["severity"] for r in tool.parse_output(json.dumps(findings))] == [
        "info", "low", "medium", "high"
    ]


# ── build_command basics ──────────────────────────────────────────────────────

def test_build_command_returns_python3(tool):
    cmd = tool.build_command(FakeTarget())
    assert cmd[0] == "python3" and cmd[1] == "-c" and isinstance(cmd[2], str)


def test_build_command_script_is_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")


def test_build_command_embeds_base_url_https(tool):
    assert "https://example.com" in tool.build_command(FakeTarget())[2]


def test_build_command_preserves_http_scheme(tool):
    assert "http://example.com" in tool.build_command(HttpTarget())[2]
