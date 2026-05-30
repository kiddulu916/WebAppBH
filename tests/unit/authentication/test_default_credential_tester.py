"""Unit tests for DefaultCredentialTester (WSTG-ATHN-02)."""
import json
import pytest

from workers.authentication.tools.default_credential_tester import DefaultCredentialTester

PAIRS_TOP10 = "/wordlists/auth/pairs_top10.txt"
PAIRS_TOP3 = "/wordlists/auth/pairs_top3.txt"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NUCLEI_HIT_JSONL = json.dumps({
    "template-id": "wordpress-default-login",
    "info": {"name": "WordPress Default Login", "severity": "critical"},
    "type": "http",
    "host": "https://example.com",
    "matched-at": "https://example.com/wp-login.php",
    "extracted-results": ["admin", "admin"],
    "matcher-status": True,
})

NUCLEI_NO_HIT_OUTPUT = ""

HYDRA_SUCCESS_OUTPUT = (
    "[DATA] attacking http-form-post://example.com:80/login\n"
    "[80][http-form-post] host: example.com   login: admin   password: password\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)

HYDRA_FAILURE_OUTPUT = (
    "[DATA] attacking http-form-post://example.com:80/login\n"
    "[DATA] max 1 task per 1 server, overall 1 task, 10 login tries\n"
    "1 of 1 target completed, 0 valid passwords found\n"
)

CAPTCHA_HTML = '<div class="g-recaptcha" data-sitekey="abc123"></div>'
CLEAN_HTML = "<html><body><form><input name='user'></form></body></html>"


# ---------------------------------------------------------------------------
# _parse_nuclei_jsonl
# ---------------------------------------------------------------------------

def test_parse_nuclei_jsonl_hit_returns_one_result():
    tool = DefaultCredentialTester()
    results = tool._parse_nuclei_jsonl(NUCLEI_HIT_JSONL)
    assert len(results) == 1


def test_parse_nuclei_jsonl_hit_extracts_credentials():
    tool = DefaultCredentialTester()
    results = tool._parse_nuclei_jsonl(NUCLEI_HIT_JSONL)
    assert results[0]["username"] == "admin"
    assert results[0]["password"] == "admin"


def test_parse_nuclei_jsonl_hit_records_template_id():
    tool = DefaultCredentialTester()
    results = tool._parse_nuclei_jsonl(NUCLEI_HIT_JSONL)
    assert results[0]["template_id"] == "wordpress-default-login"


def test_parse_nuclei_jsonl_hit_records_url():
    tool = DefaultCredentialTester()
    results = tool._parse_nuclei_jsonl(NUCLEI_HIT_JSONL)
    assert results[0]["url"] == "https://example.com/wp-login.php"


def test_parse_nuclei_jsonl_no_output_returns_empty():
    tool = DefaultCredentialTester()
    results = tool._parse_nuclei_jsonl(NUCLEI_NO_HIT_OUTPUT)
    assert results == []


def test_parse_nuclei_jsonl_skips_malformed_lines():
    tool = DefaultCredentialTester()
    mixed = "not json at all\n" + NUCLEI_HIT_JSONL
    results = tool._parse_nuclei_jsonl(mixed)
    assert len(results) == 1


def test_parse_nuclei_jsonl_no_extracted_results_yields_empty_creds():
    tool = DefaultCredentialTester()
    no_extract = json.dumps({
        "template-id": "generic-default-login",
        "matched-at": "https://example.com/admin",
        "extracted-results": [],
    })
    results = tool._parse_nuclei_jsonl(no_extract)
    assert results[0]["username"] == ""
    assert results[0]["password"] == ""


# ---------------------------------------------------------------------------
# _parse_hydra_output
# ---------------------------------------------------------------------------

def test_parse_hydra_output_hit_returns_credentials():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/login", is_basic_auth=False)
    assert len(results) == 1
    assert results[0]["username"] == "admin"
    assert results[0]["password"] == "password"


def test_parse_hydra_output_hit_auth_type_form():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/login", is_basic_auth=False)
    assert results[0]["auth_type"] == "form"


def test_parse_hydra_output_hit_auth_type_basic():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/manager", is_basic_auth=True)
    assert results[0]["auth_type"] == "basic"


def test_parse_hydra_output_failure_returns_empty():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_FAILURE_OUTPUT, "https://example.com/login", is_basic_auth=False)
    assert results == []


def test_parse_hydra_output_empty_stdout_returns_empty():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output("", "https://example.com/login", is_basic_auth=False)
    assert results == []


# ---------------------------------------------------------------------------
# _is_captcha_protected
# ---------------------------------------------------------------------------

def test_is_captcha_protected_detects_recaptcha():
    tool = DefaultCredentialTester()
    assert tool._is_captcha_protected(CAPTCHA_HTML) is True


def test_is_captcha_protected_detects_hcaptcha():
    tool = DefaultCredentialTester()
    assert tool._is_captcha_protected('<div class="h-captcha">') is True


def test_is_captcha_protected_detects_turnstile():
    tool = DefaultCredentialTester()
    assert tool._is_captcha_protected('<div class="cf-turnstile">') is True


def test_is_captcha_protected_clean_page_returns_false():
    tool = DefaultCredentialTester()
    assert tool._is_captcha_protected(CLEAN_HTML) is False


def test_is_captcha_protected_empty_returns_false():
    tool = DefaultCredentialTester()
    assert tool._is_captcha_protected("") is False


# ---------------------------------------------------------------------------
# _select_hydra_pairs
# ---------------------------------------------------------------------------

def test_select_hydra_pairs_lockout_at_5_returns_top3():
    tool = DefaultCredentialTester()
    assert tool._select_hydra_pairs(lockout_threshold=5) == PAIRS_TOP3


def test_select_hydra_pairs_lockout_at_3_returns_top3():
    tool = DefaultCredentialTester()
    assert tool._select_hydra_pairs(lockout_threshold=3) == PAIRS_TOP3


def test_select_hydra_pairs_lockout_at_6_returns_top10():
    tool = DefaultCredentialTester()
    assert tool._select_hydra_pairs(lockout_threshold=6) == PAIRS_TOP10


def test_select_hydra_pairs_no_lockout_returns_top10():
    tool = DefaultCredentialTester()
    assert tool._select_hydra_pairs(lockout_threshold=None) == PAIRS_TOP10


# ---------------------------------------------------------------------------
# _has_lockout_signal
# ---------------------------------------------------------------------------

def test_has_lockout_signal_detects_too_many():
    tool = DefaultCredentialTester()
    assert tool._has_lockout_signal("Error: too many login attempts") is True


def test_has_lockout_signal_detects_account_locked():
    tool = DefaultCredentialTester()
    assert tool._has_lockout_signal("Your account locked after 5 failures") is True


def test_has_lockout_signal_detects_temporarily_blocked():
    tool = DefaultCredentialTester()
    assert tool._has_lockout_signal("temporarily blocked") is True


def test_has_lockout_signal_clean_output_returns_false():
    tool = DefaultCredentialTester()
    assert tool._has_lockout_signal("1 of 1 target completed, 0 valid passwords found") is False


# ---------------------------------------------------------------------------
# _rotate_ip
# ---------------------------------------------------------------------------

def test_rotate_ip_empty_pool_returns_none():
    tool = DefaultCredentialTester()
    assert tool._rotate_ip([], 0) is None


def test_rotate_ip_single_ip_always_returns_it():
    tool = DefaultCredentialTester()
    assert tool._rotate_ip(["1.2.3.4"], 0) == "1.2.3.4"
    assert tool._rotate_ip(["1.2.3.4"], 99) == "1.2.3.4"


def test_rotate_ip_cycles_through_pool():
    tool = DefaultCredentialTester()
    pool = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert tool._rotate_ip(pool, 0) == "10.0.0.1"
    assert tool._rotate_ip(pool, 1) == "10.0.0.2"
    assert tool._rotate_ip(pool, 2) == "10.0.0.3"
    assert tool._rotate_ip(pool, 3) == "10.0.0.1"


# ---------------------------------------------------------------------------
# _build_nuclei_cmd
# ---------------------------------------------------------------------------

def test_build_nuclei_cmd_includes_rate_limit():
    tool = DefaultCredentialTester()
    cmd = tool._build_nuclei_cmd("/tmp/urls.txt", pps=5, custom_headers={}, rotated_ip=None)
    assert "-rate-limit" in cmd
    assert cmd[cmd.index("-rate-limit") + 1] == "5"


def test_build_nuclei_cmd_includes_both_template_dirs():
    tool = DefaultCredentialTester()
    cmd = tool._build_nuclei_cmd("/tmp/urls.txt", pps=10, custom_headers={}, rotated_ip=None)
    cmd_str = " ".join(cmd)
    assert "/nuclei-templates/community/http/default-logins/" in cmd_str
    assert "/nuclei-templates/custom/" in cmd_str


def test_build_nuclei_cmd_adds_xforwardedfor_when_ip_given():
    tool = DefaultCredentialTester()
    cmd = tool._build_nuclei_cmd("/tmp/urls.txt", pps=10, custom_headers={}, rotated_ip="1.2.3.4")
    cmd_str = " ".join(cmd)
    assert "X-Forwarded-For: 1.2.3.4" in cmd_str


def test_build_nuclei_cmd_no_xforwardedfor_when_no_ip():
    tool = DefaultCredentialTester()
    cmd = tool._build_nuclei_cmd("/tmp/urls.txt", pps=10, custom_headers={}, rotated_ip=None)
    cmd_str = " ".join(cmd)
    assert "X-Forwarded-For" not in cmd_str


def test_build_nuclei_cmd_includes_custom_headers():
    tool = DefaultCredentialTester()
    cmd = tool._build_nuclei_cmd("/tmp/urls.txt", pps=10, custom_headers={"X-Custom": "val"}, rotated_ip=None)
    cmd_str = " ".join(cmd)
    assert "X-Custom: val" in cmd_str


def test_build_nuclei_cmd_no_interactsh_flag():
    tool = DefaultCredentialTester()
    cmd = tool._build_nuclei_cmd("/tmp/urls.txt", pps=10, custom_headers={}, rotated_ip=None)
    assert "-no-interactsh" in cmd


# ---------------------------------------------------------------------------
# _build_hydra_cmd
# ---------------------------------------------------------------------------

def test_build_hydra_cmd_single_thread():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/login",
        pairs_file=PAIRS_TOP10,
        hydra_wait=15,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=False,
    )
    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == "1"


def test_build_hydra_cmd_stop_at_first():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/login",
        pairs_file=PAIRS_TOP10,
        hydra_wait=15,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=False,
    )
    assert "-f" in cmd


def test_build_hydra_cmd_wait_flag():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/login",
        pairs_file=PAIRS_TOP10,
        hydra_wait=20,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=False,
    )
    assert "-w" in cmd
    assert cmd[cmd.index("-w") + 1] == "20"


def test_build_hydra_cmd_basic_auth_uses_http_get():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/manager/html",
        pairs_file=PAIRS_TOP10,
        hydra_wait=15,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=True,
    )
    assert "http-get" in cmd


def test_build_hydra_cmd_https_basic_auth_uses_https_get():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="https://example.com/manager/html",
        pairs_file=PAIRS_TOP10,
        hydra_wait=15,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=True,
    )
    assert "https-get" in cmd


def test_build_hydra_cmd_form_uses_http_form_post():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/login",
        pairs_file=PAIRS_TOP10,
        hydra_wait=15,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=False,
    )
    assert "http-form-post" in cmd


def test_build_hydra_cmd_xforwardedfor_in_form_module_string():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/login",
        pairs_file=PAIRS_TOP10,
        hydra_wait=15,
        custom_headers={},
        rotated_ip="1.2.3.4",
        is_basic_auth=False,
    )
    cmd_str = " ".join(cmd)
    assert "X-Forwarded-For: 1.2.3.4" in cmd_str


def test_build_hydra_cmd_uses_pairs_file():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_cmd(
        url="http://example.com/login",
        pairs_file=PAIRS_TOP3,
        hydra_wait=15,
        custom_headers={},
        rotated_ip=None,
        is_basic_auth=False,
    )
    assert "-C" in cmd
    assert cmd[cmd.index("-C") + 1] == PAIRS_TOP3


# ---------------------------------------------------------------------------
# _load_settings (uses temp files)
# ---------------------------------------------------------------------------

def test_load_settings_defaults_when_no_files(tmp_path):
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["pps"] == 10
    assert settings["hydra_wait"] == 15
    assert settings["proxy_pool"] == []
    assert settings["custom_headers"] == {}


def test_load_settings_reads_pps_from_rate_limits(tmp_path):
    (tmp_path / "rate_limits.json").write_text('{"pps": 5}')
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["pps"] == 5


def test_load_settings_reads_hydra_wait(tmp_path):
    (tmp_path / "default_creds.json").write_text('{"hydra_wait_secs": 30}')
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["hydra_wait"] == 30


def test_load_settings_enforces_minimum_hydra_wait(tmp_path):
    (tmp_path / "default_creds.json").write_text('{"hydra_wait_secs": 2}')
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["hydra_wait"] == 5


def test_load_settings_reads_proxy_pool(tmp_path):
    (tmp_path / "default_creds.json").write_text('{"proxy_pool": ["1.1.1.1", "2.2.2.2"]}')
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["proxy_pool"] == ["1.1.1.1", "2.2.2.2"]


def test_load_settings_reads_custom_headers(tmp_path):
    (tmp_path / "custom_headers.json").write_text('{"X-Custom": "hello"}')
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["custom_headers"] == {"X-Custom": "hello"}


def test_load_settings_nuclei_rate_overrides_pps(tmp_path):
    (tmp_path / "rate_limits.json").write_text('{"pps": 20}')
    (tmp_path / "default_creds.json").write_text('{"nuclei_rate_limit": 3}')
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["pps"] == 3


def test_load_settings_tolerates_malformed_json(tmp_path):
    (tmp_path / "rate_limits.json").write_text("not json {{{")
    tool = DefaultCredentialTester()
    settings = tool._load_settings_from_dir(tmp_path)
    assert settings["pps"] == 10
