"""Unit tests for AuthBypassTester sync helpers (WSTG-ATHN-04)."""
from types import SimpleNamespace
import pytest

from workers.authentication.tools.auth_bypass_tester import AuthBypassTester


def _resp(status_code: int, text: str = "", location: str = "", headers: dict | None = None) -> SimpleNamespace:
    """Build a minimal response object for testing helpers."""
    h = dict(headers or {})
    if location:
        h["location"] = location
    return SimpleNamespace(status_code=status_code, text=text, headers=h)


# ---------------------------------------------------------------------------
# _is_protected
# ---------------------------------------------------------------------------

def test_is_protected_none_returns_true():
    assert AuthBypassTester()._is_protected(None) is True

def test_is_protected_401_returns_true():
    assert AuthBypassTester()._is_protected(_resp(401)) is True

def test_is_protected_403_returns_true():
    assert AuthBypassTester()._is_protected(_resp(403)) is True

def test_is_protected_redirect_to_login_returns_true():
    assert AuthBypassTester()._is_protected(_resp(302, location="/login")) is True

def test_is_protected_redirect_to_signin_returns_true():
    assert AuthBypassTester()._is_protected(_resp(302, location="/signin")) is True

def test_is_protected_redirect_to_auth_returns_true():
    assert AuthBypassTester()._is_protected(_resp(302, location="/auth/login")) is True

def test_is_protected_redirect_to_unauthorized_returns_true():
    assert AuthBypassTester()._is_protected(_resp(302, location="/unauthorized")) is True

def test_is_protected_307_redirect_to_login_returns_true():
    assert AuthBypassTester()._is_protected(_resp(307, location="/login")) is True

def test_is_protected_body_login_required_returns_true():
    assert AuthBypassTester()._is_protected(_resp(200, text="login required")) is True

def test_is_protected_body_access_denied_returns_true():
    assert AuthBypassTester()._is_protected(_resp(200, text="access denied")) is True

def test_is_protected_200_normal_content_returns_false():
    assert AuthBypassTester()._is_protected(_resp(200, text="Welcome to the dashboard")) is False

def test_is_protected_302_to_home_returns_false():
    assert AuthBypassTester()._is_protected(_resp(302, location="/home")) is False


# ---------------------------------------------------------------------------
# _is_rate_limited
# ---------------------------------------------------------------------------

def test_is_rate_limited_none_returns_false():
    assert AuthBypassTester()._is_rate_limited(None) is False

def test_is_rate_limited_429_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(429)) is True

def test_is_rate_limited_body_too_many_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="too many requests")) is True

def test_is_rate_limited_body_blocked_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="your ip is blocked")) is True

def test_is_rate_limited_body_rate_limit_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="rate limit exceeded")) is True

def test_is_rate_limited_200_normal_returns_false():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="Welcome")) is False


# ---------------------------------------------------------------------------
# _load_settings_from_dir
# ---------------------------------------------------------------------------

def test_load_settings_defaults_when_no_files(tmp_path):
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["probe_delay_secs"] == 0.3
    assert s["forced_browsing_delay_secs"] == 0.3
    assert s["sqli_delay_secs"] == 2.0
    assert s["ip_rotation_pool"] == []
    assert s["max_sqli_payloads"] == 15
    assert s["custom_headers"] == {}
    assert len(s["user_agents"]) == 5  # falls back to _DEFAULT_USER_AGENTS (5 built-in entries)

def test_load_settings_reads_probe_delay_from_rate_limits(tmp_path):
    (tmp_path / "rate_limits.json").write_text('{"probe_delay_secs": 1.5}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["probe_delay_secs"] == 1.5

def test_load_settings_reads_sqli_delay_from_bypass(tmp_path):
    (tmp_path / "bypass.json").write_text('{"sqli_delay_secs": 5.0}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["sqli_delay_secs"] == 5.0

def test_load_settings_reads_ip_rotation_pool(tmp_path):
    (tmp_path / "bypass.json").write_text('{"ip_rotation_pool": ["1.1.1.1", "2.2.2.2"]}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["ip_rotation_pool"] == ["1.1.1.1", "2.2.2.2"]

def test_load_settings_empty_user_agents_falls_back_to_defaults(tmp_path):
    (tmp_path / "bypass.json").write_text('{"user_agents": []}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert len(s["user_agents"]) == 5  # _DEFAULT_USER_AGENTS has 5 entries

def test_load_settings_custom_user_agents_override_defaults(tmp_path):
    (tmp_path / "bypass.json").write_text('{"user_agents": ["MyBot/1.0"]}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["user_agents"] == ["MyBot/1.0"]

def test_load_settings_reads_custom_headers(tmp_path):
    (tmp_path / "custom_headers.json").write_text('{"Authorization": "Bearer tok"}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["custom_headers"] == {"Authorization": "Bearer tok"}

def test_load_settings_tolerates_malformed_json(tmp_path):
    (tmp_path / "bypass.json").write_text("not json {{{{")
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["sqli_delay_secs"] == 2.0  # falls back to default

def test_load_settings_reads_max_sqli_payloads(tmp_path):
    (tmp_path / "bypass.json").write_text('{"max_sqli_payloads": 5}')
    s = AuthBypassTester()._load_settings_from_dir(tmp_path)
    assert s["max_sqli_payloads"] == 5
