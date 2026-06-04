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


# ---------------------------------------------------------------------------
# _parse_form_fields
# ---------------------------------------------------------------------------

def test_parse_form_fields_extracts_password_field_name():
    html = '<form><input type="text" name="user"><input type="password" name="pass"></form>'
    _, pw = AuthBypassTester()._parse_form_fields(html)
    assert pw == "pass"

def test_parse_form_fields_extracts_username_field_name():
    html = '<form><input type="text" name="user"><input type="password" name="pass"></form>'
    un, _ = AuthBypassTester()._parse_form_fields(html)
    assert un == "user"

def test_parse_form_fields_detects_email_type_as_username():
    html = '<form><input type="email" name="email_addr"><input type="password" name="pwd"></form>'
    un, _ = AuthBypassTester()._parse_form_fields(html)
    assert un == "email_addr"

def test_parse_form_fields_reversed_attribute_order():
    html = '<form><input name="pass" type="password"><input name="user" type="text"></form>'
    un, pw = AuthBypassTester()._parse_form_fields(html)
    assert pw == "pass"
    assert un == "user"

def test_parse_form_fields_falls_back_to_defaults_when_no_inputs():
    html = "<form><button type='submit'>Login</button></form>"
    un, pw = AuthBypassTester()._parse_form_fields(html)
    assert un == "username"
    assert pw == "password"

def test_parse_form_fields_case_insensitive():
    html = '<form><INPUT TYPE="PASSWORD" NAME="PW"><INPUT TYPE="TEXT" NAME="UN"></form>'
    un, pw = AuthBypassTester()._parse_form_fields(html)
    assert pw == "PW"
    assert un == "UN"


# ---------------------------------------------------------------------------
# _parse_form_action
# ---------------------------------------------------------------------------

def test_parse_form_action_extracts_relative_action():
    html = '<form action="/do_login" method="post"><input name="u"></form>'
    action = AuthBypassTester()._parse_form_action(html, "https://example.com/login")
    assert action == "https://example.com/do_login"

def test_parse_form_action_extracts_absolute_action():
    html = '<form action="https://other.com/auth"><input name="u"></form>'
    action = AuthBypassTester()._parse_form_action(html, "https://example.com/login")
    assert action == "https://other.com/auth"

def test_parse_form_action_falls_back_to_login_url_when_no_form():
    html = "<html><body>No form here</body></html>"
    action = AuthBypassTester()._parse_form_action(html, "https://example.com/login")
    assert action == "https://example.com/login"


# ---------------------------------------------------------------------------
# _extract_jwt
# ---------------------------------------------------------------------------

_SAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def test_extract_jwt_finds_token_cookie():
    r = _resp(200, headers={"set-cookie": f"token={_SAMPLE_JWT}; Path=/"})
    result = AuthBypassTester()._extract_jwt(r)
    assert result == _SAMPLE_JWT

def test_extract_jwt_finds_jwt_cookie_name():
    r = _resp(200, headers={"set-cookie": f"jwt={_SAMPLE_JWT}; HttpOnly"})
    result = AuthBypassTester()._extract_jwt(r)
    assert result == _SAMPLE_JWT

def test_extract_jwt_returns_none_when_no_jwt():
    r = _resp(200, headers={"set-cookie": "PHPSESSID=abc123; Path=/"})
    result = AuthBypassTester()._extract_jwt(r)
    assert result is None

def test_extract_jwt_returns_none_when_no_set_cookie():
    r = _resp(200)
    result = AuthBypassTester()._extract_jwt(r)
    assert result is None


# ---------------------------------------------------------------------------
# _build_none_jwt
# ---------------------------------------------------------------------------

def test_build_none_jwt_changes_alg_to_none():
    none_jwt = AuthBypassTester()._build_none_jwt(_SAMPLE_JWT)
    import base64
    header_b64 = none_jwt.split(".")[0]
    padding = 4 - len(header_b64) % 4
    if padding != 4:
        header_b64 += "=" * padding
    header = base64.urlsafe_b64decode(header_b64).decode()
    assert '"alg":"none"' in header

def test_build_none_jwt_preserves_original_payload():
    none_jwt = AuthBypassTester()._build_none_jwt(_SAMPLE_JWT)
    original_payload = _SAMPLE_JWT.split(".")[1]
    assert none_jwt.split(".")[1] == original_payload

def test_build_none_jwt_has_empty_signature():
    none_jwt = AuthBypassTester()._build_none_jwt(_SAMPLE_JWT)
    assert none_jwt.endswith(".")

def test_build_none_jwt_returns_input_on_malformed_token():
    bad_token = "not.a.valid.jwt.token.with.too.many.parts"
    result = AuthBypassTester()._build_none_jwt(bad_token)
    assert result == bad_token


# ---------------------------------------------------------------------------
# _estimate_entropy
# ---------------------------------------------------------------------------

def test_estimate_entropy_sequential_numeric_ids_flagged():
    ids = [str(i) for i in range(1000, 1015)]  # 1000, 1001, ..., 1014
    _, is_sequential = AuthBypassTester()._estimate_entropy(ids)
    assert is_sequential is True

def test_estimate_entropy_sequential_hex_ids_flagged():
    ids = [hex(i)[2:] for i in range(0xA000, 0xA00F)]  # a000, a001, ..., a00e
    _, is_sequential = AuthBypassTester()._estimate_entropy(ids)
    assert is_sequential is True

def test_estimate_entropy_high_entropy_not_sequential():
    import secrets
    ids = [secrets.token_hex(16) for _ in range(15)]
    _, is_sequential = AuthBypassTester()._estimate_entropy(ids)
    assert is_sequential is False

def test_estimate_entropy_short_ids_low_entropy():
    ids = ["ab12", "cd34", "ef56", "gh78", "ij90"] * 3  # 15 short IDs
    entropy_bits, _ = AuthBypassTester()._estimate_entropy(ids)
    assert entropy_bits < 32

def test_estimate_entropy_empty_list_returns_zero():
    entropy_bits, is_sequential = AuthBypassTester()._estimate_entropy([])
    assert entropy_bits == 0.0
    assert is_sequential is False

def test_estimate_entropy_long_random_ids_above_64_bits():
    import secrets
    ids = [secrets.token_hex(32) for _ in range(15)]  # 64-char hex = 256 bits
    entropy_bits, _ = AuthBypassTester()._estimate_entropy(ids)
    assert entropy_bits > 64
