"""Unit tests for AdminParamTamperer pure functions (WSTG-CONF-05)."""
import pytest

from workers.config_mgmt.tools.admin_param_tamperer import (
    AdminParamTamperer,
    _build_flip_values,
    _classify_tamper_response,
    _extract_hidden_inputs,
    _filter_admin_params,
)


# ── _extract_hidden_inputs ────────────────────────────────────────────────────

def test_extract_hidden_inputs_finds_hidden_field():
    html = '<form><input type="hidden" name="admin" value="0"/></form>'
    result = _extract_hidden_inputs(html)
    assert ("admin", "0") in result


def test_extract_hidden_inputs_ignores_visible_inputs():
    html = '<form><input type="text" name="username" value="user"/></form>'
    result = _extract_hidden_inputs(html)
    assert ("username", "user") not in result


def test_extract_hidden_inputs_handles_missing_value():
    html = '<form><input type="hidden" name="debug"/></form>'
    result = _extract_hidden_inputs(html)
    assert ("debug", "") in result


def test_extract_hidden_inputs_empty_html_returns_empty():
    assert _extract_hidden_inputs("") == []


def test_extract_hidden_inputs_no_hidden_fields_returns_empty():
    html = '<form><input type="text" name="q"/></form>'
    assert _extract_hidden_inputs(html) == []


def test_extract_hidden_inputs_multiple_fields():
    html = """<form>
        <input type="hidden" name="admin" value="0"/>
        <input type="hidden" name="role" value="user"/>
    </form>"""
    result = _extract_hidden_inputs(html)
    assert ("admin", "0") in result
    assert ("role", "user") in result


# ── _filter_admin_params ──────────────────────────────────────────────────────

def test_filter_admin_params_keeps_admin_param():
    result = _filter_admin_params([("admin", "0"), ("username", "alice")])
    assert ("admin", "0") in result


def test_filter_admin_params_removes_non_suspicious_param():
    result = _filter_admin_params([("username", "alice"), ("email", "a@b.com")])
    assert ("username", "alice") not in result
    assert ("email", "a@b.com") not in result


def test_filter_admin_params_keeps_role_param():
    result = _filter_admin_params([("role", "user")])
    assert ("role", "user") in result


def test_filter_admin_params_keeps_is_admin_param():
    result = _filter_admin_params([("is_admin", "false")])
    assert ("is_admin", "false") in result


def test_filter_admin_params_keeps_debug_param():
    result = _filter_admin_params([("debug", "0")])
    assert ("debug", "0") in result


def test_filter_admin_params_empty_input_returns_empty():
    assert _filter_admin_params([]) == []


def test_filter_admin_params_partial_match():
    result = _filter_admin_params([("useradmin", "0")])
    assert ("useradmin", "0") in result


# ── _build_flip_values ────────────────────────────────────────────────────────

def test_build_flip_values_zero_becomes_one():
    result = _build_flip_values("0")
    assert "1" in result


def test_build_flip_values_false_becomes_true():
    result = _build_flip_values("false")
    assert "true" in result


def test_build_flip_values_no_becomes_yes():
    result = _build_flip_values("no")
    assert "yes" in result


def test_build_flip_values_user_becomes_admin():
    result = _build_flip_values("user")
    assert "admin" in result


def test_build_flip_values_guest_becomes_admin():
    result = _build_flip_values("guest")
    assert "admin" in result


def test_build_flip_values_unknown_value_includes_admin_and_one():
    result = _build_flip_values("xyz_unknown")
    assert "admin" in result
    assert "1" in result


def test_build_flip_values_returns_list():
    assert isinstance(_build_flip_values("0"), list)


# ── _classify_tamper_response ─────────────────────────────────────────────────

def test_classify_tamper_status_bypass_is_critical():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=403, new_status=200,
        baseline_len=100, new_len=100, new_body="some content",
    )
    assert severity == "critical"
    assert vuln_type == "parameter_tampering_bypass"


def test_classify_tamper_redirect_bypass_is_critical():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=302, new_status=200,
        baseline_len=100, new_len=500, new_body="dashboard panel",
    )
    assert severity == "critical"
    assert vuln_type == "parameter_tampering_bypass"


def test_classify_tamper_admin_keyword_in_body_is_high():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=150, new_body="welcome to the admin dashboard",
    )
    assert severity == "high"
    assert vuln_type == "parameter_tampering_escalation"


def test_classify_tamper_large_body_change_is_medium():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=200, new_body="some regular content here",
    )
    assert severity == "medium"
    assert vuln_type == "parameter_tampering_indicator"


def test_classify_tamper_no_change_returns_none():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=102, new_body="same content roughly",
    )
    assert severity is None
    assert vuln_type is None


def test_classify_tamper_admin_keywords_panel():
    severity, _ = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=110, new_body="control panel settings",
    )
    assert severity == "high"


def test_classify_tamper_admin_keywords_users():
    severity, _ = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=110, new_body="manage users configuration",
    )
    assert severity == "high"


# ── AdminParamTamperer class ──────────────────────────────────────────────────

def test_tool_has_correct_name():
    assert AdminParamTamperer.name == "admin_param_tamperer"


def test_build_command_raises():
    tool = AdminParamTamperer()
    with pytest.raises(NotImplementedError):
        tool.build_command(object())


def test_parse_output_raises():
    tool = AdminParamTamperer()
    with pytest.raises(NotImplementedError):
        tool.parse_output("")
