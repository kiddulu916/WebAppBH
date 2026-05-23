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


# ── Block 2: Privilege escalation ────────────────────────────────────────────

def test_build_command_has_role_admin(tool):
    script = tool.build_command(FakeTarget())[2]
    assert '"role"' in script and '"admin"' in script


def test_build_command_has_is_admin(tool):
    assert "is_admin" in tool.build_command(FakeTarget())[2]


def test_build_command_has_account_type(tool):
    assert "account_type" in tool.build_command(FakeTarget())[2]


def test_build_command_has_permissions(tool):
    assert '"permissions"' in tool.build_command(FakeTarget())[2]


def test_build_command_block2_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")


# ── Block 3: Password policy ──────────────────────────────────────────────────

def test_build_command_has_weak_passwords(tool):
    assert "weak_passwords" in tool.build_command(FakeTarget())[2]


def test_build_command_weak_passwords_has_123456(tool):
    assert "123456" in tool.build_command(FakeTarget())[2]


def test_build_command_weak_passwords_has_password(tool):
    script = tool.build_command(FakeTarget())[2]
    assert '"password"' in script or "'password'" in script


def test_build_command_block3_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")


# ── Block 4: Duplicate account & enumeration ──────────────────────────────────

def test_build_command_has_dup_email(tool):
    assert "dup_email" in tool.build_command(FakeTarget())[2]


def test_build_command_has_reveal_patterns(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "reveal_patterns" in script and "already" in script


def test_build_command_has_timing_delta(tool):
    assert "monotonic" in tool.build_command(FakeTarget())[2]


def test_build_command_block4_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")


# ── Block 5: Email verification ───────────────────────────────────────────────

def test_build_command_has_tempmail(tool):
    assert "tempmail" in tool.build_command(FakeTarget())[2]


def test_build_command_has_mailinator(tool):
    assert "mailinator" in tool.build_command(FakeTarget())[2]


def test_build_command_has_notanemail(tool):
    assert "notanemail" in tool.build_command(FakeTarget())[2]


def test_build_command_has_verify_keyword(tool):
    assert "verify_keywords" in tool.build_command(FakeTarget())[2]


def test_build_command_block5_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")


# ── Block 6: Rate limiting & bot protection ────────────────────────────────────

def test_build_command_has_15_attempt_loop(tool):
    assert "range(15)" in tool.build_command(FakeTarget())[2]


def test_build_command_rate_limit_rotates_client(tool):
    script = tool.build_command(FakeTarget())[2]
    # make_client() appears multiple times (evasion + block 6 per-attempt)
    assert script.count("make_client()") >= 2


def test_build_command_has_captcha_patterns(tool):
    script = tool.build_command(FakeTarget())[2]
    assert "g-recaptcha" in script and "captcha_patterns" in script


def test_build_command_block6_valid_python(tool):
    compile(tool.build_command(FakeTarget())[2], "<string>", "exec")
