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


# ── Evasion layer ─────────────────────────────────────────────────────────────

def test_build_command_has_user_agents_pool(tool):
    assert "USER_AGENTS" in tool.build_command(FakeTarget())[2]


def test_build_command_has_xff_header(tool):
    assert "X-Forwarded-For" in tool.build_command(FakeTarget())[2]


def test_build_command_has_make_client(tool):
    assert "make_client" in tool.build_command(FakeTarget())[2]


def test_build_command_has_safe_request(tool):
    assert "safe_request" in tool.build_command(FakeTarget())[2]


def test_build_command_has_429_backoff(tool):
    assert "429" in tool.build_command(FakeTarget())[2]


def test_build_command_has_jitter(tool):
    assert "uniform" in tool.build_command(FakeTarget())[2]


def test_build_command_evasion_script_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")


# ── Block 1: Endpoint discovery & protocol check ──────────────────────────────

def test_build_command_has_reg_paths(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "reg_paths" in script
    assert "/register" in script and "/join" in script


def test_build_command_has_csrf_check(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "_token" in script and "csrf" in script.lower()


def test_build_command_has_https_enforcement(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "follow_redirects=False" in script
    assert "301" in script or "302" in script


def test_build_command_block1_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")
