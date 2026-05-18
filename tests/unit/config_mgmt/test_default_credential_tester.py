"""Unit tests for DefaultCredentialTester (WSTG-CONF-01 pillar 3)."""
import pytest

from workers.config_mgmt.tools.default_credential_tester import DefaultCredentialTester


HYDRA_SUCCESS_OUTPUT = (
    "[DATA] attacking http-form-post://example.com:80/wp-login.php\n"
    "[80][http-form-post] host: example.com   login: admin   password: admin\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)

HYDRA_FAILURE_OUTPUT = (
    "[DATA] attacking http-form-post://example.com:80/admin\n"
    "[DATA] max 1 task per 1 server, overall 1 task, 6 login tries (l:2/p:3)\n"
    "1 of 1 target completed, 0 valid passwords found\n"
)

HYDRA_EMPTY_OUTPUT = ""


def test_parse_hydra_success_yields_critical_vulnerability():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/wp-login.php")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 1
    assert vulns[0]["vulnerability"]["severity"] == "critical"
    assert "admin" in vulns[0]["vulnerability"]["description"]


def test_parse_hydra_success_includes_credential_test_result_observation():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/wp-login.php")
    obs = [r for r in results if "observation" in r]
    assert len(obs) == 1
    assert obs[0]["observation"]["type"] == "credential_test_result"
    assert obs[0]["observation"]["details"]["outcome"] == "credentials_found"
    assert obs[0]["observation"]["details"]["credentials_found"] == 1


def test_parse_hydra_failure_yields_no_vulnerability():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_FAILURE_OUTPUT, "https://example.com/admin")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 0


def test_parse_hydra_failure_yields_no_credentials_found_observation():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_FAILURE_OUTPUT, "https://example.com/admin")
    obs = [r for r in results if "observation" in r]
    assert len(obs) == 1
    assert obs[0]["observation"]["details"]["outcome"] == "no_credentials_found"
    assert obs[0]["observation"]["details"]["credentials_found"] == 0


def test_parse_hydra_empty_output_yields_only_observation():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_EMPTY_OUTPUT, "https://example.com/admin")
    assert len(results) == 1
    assert "observation" in results[0]


def test_get_profile_wordpress_path():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/wp-admin")
    assert "admin" in profile["users"]
    assert "is wrong" in profile["failure_string"]
    assert profile["module"] == "http-form-post"


def test_get_profile_wordpress_login_path():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/wp-login.php")
    assert "admin" in profile["users"]


def test_get_profile_tomcat():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/manager/html")
    assert "tomcat" in profile["users"]
    assert "s3cret" in profile["passwords"]


def test_get_profile_jenkins():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/jenkins")
    assert "admin" in profile["users"]


def test_get_profile_unknown_path_returns_generic():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/some-unknown-panel")
    assert "admin" in profile["users"]
    assert "admin" in profile["passwords"]
    assert profile["module"] == "http-form-post"


def test_build_hydra_command_single_thread():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=80, path="/admin",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=3, ua="Mozilla/5.0", failure_string="invalid", module="http-form-post",
    )
    assert cmd[0] == "hydra"
    assert "-t" in cmd
    t_index = cmd.index("-t")
    assert cmd[t_index + 1] == "1"


def test_build_hydra_command_has_wait_flag():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=80, path="/admin",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=5, ua="Firefox/125.0", failure_string="failed", module="http-form-post",
    )
    assert "-w" in cmd
    w_index = cmd.index("-w")
    assert cmd[w_index + 1] == "5"


def test_build_hydra_command_embeds_ua_in_module_string():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=80, path="/admin",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=3, ua="Chrome/124.0", failure_string="invalid", module="http-form-post",
    )
    cmd_str = " ".join(cmd)
    assert "Chrome/124.0" in cmd_str


def test_build_hydra_command_http_get_module_uses_path_only():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=8983, path="/solr",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=3, ua="Mozilla/5.0", failure_string="Unauthorized", module="http-get",
    )
    assert "http-get" in cmd
    idx = cmd.index("http-get")
    assert cmd[idx + 1] == "/solr"
    assert "^USER^" not in " ".join(cmd)


def test_build_command_returns_true_placeholder():
    tool = DefaultCredentialTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert cmd == ["true"]
