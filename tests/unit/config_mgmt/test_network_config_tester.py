"""Unit tests for refactored NetworkConfigTester (WSTG-CONF-01 pillar 1)."""
import json
import pytest

from workers.config_mgmt.tools.network_config_tester import NetworkConfigTester


def test_parse_output_server_banner_observation():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "observation": {
            "type": "server_banner",
            "value": "Apache/2.4.49",
            "details": {"header": "server", "product": "apache", "version": "2.4.49"},
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "server_banner"
    assert results[0]["observation"]["details"]["product"] == "apache"
    assert results[0]["observation"]["details"]["version"] == "2.4.49"


def test_parse_output_high_cvss_yields_vulnerability():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "vulnerability": {
            "name": "CVE-2021-41773: apache 2.4.49",
            "severity": "critical",
            "description": "Path traversal in Apache 2.4.49",
            "location": "https://example.com",
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "critical"
    assert "CVE-2021-41773" in results[0]["vulnerability"]["name"]


def test_parse_output_low_cvss_yields_server_cve_low_observation():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "observation": {
            "type": "server_cve_low",
            "value": "CVE-2021-12345",
            "details": {
                "product": "apache", "version": "2.4.49",
                "base_score": 5.3, "description": "Low risk issue",
            },
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "server_cve_low"
    assert results[0]["observation"]["details"]["base_score"] == 5.3


def test_parse_output_empty_stdout_returns_empty_list():
    tool = NetworkConfigTester()
    assert tool.parse_output("") == []


def test_parse_output_invalid_json_returns_empty_list():
    tool = NetworkConfigTester()
    assert tool.parse_output("not json at all") == []


def test_build_command_returns_python3_subprocess():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    assert isinstance(cmd[2], str)


def test_build_command_script_contains_nvd_api_call():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert "nvd.nist.gov" in cmd[2]


def test_build_command_script_contains_server_banner_emission():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert "server_banner" in cmd[2]


def test_build_command_script_has_no_cors_logic():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert "access-control-allow-origin" not in cmd[2].lower()
    assert "cors" not in cmd[2].lower()
    assert "evil.com" not in cmd[2]


def test_build_command_script_uses_version_headers():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    script = cmd[2]
    assert "x-powered-by" in script.lower()
    assert "x-aspnet-version" in script.lower()
