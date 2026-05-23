"""Unit tests for refactored NetworkConfigTester (WSTG-CONF-01 pillar 1)."""
import json
import pytest

from workers.config_mgmt.tools.network_config_tester import NetworkConfigTester


def test_parse_output_server_banner_is_low_vulnerability():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "vulnerability": {
            "name": "Server software version disclosed: Apache/2.4.49",
            "severity": "low",
            "description": (
                "The server disclosed its software version in the server header: "
                "Apache/2.4.49. Version disclosure enables targeted exploitation "
                "of known CVEs."
            ),
            "location": "https://example.com",
            "section_id": "WSTG-CONF-01",
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "low"
    assert "Apache/2.4.49" in results[0]["vulnerability"]["name"]
    assert results[0]["vulnerability"]["section_id"] == "WSTG-CONF-01"


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


def test_parse_output_low_cvss_yields_low_vulnerability():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "vulnerability": {
            "name": "CVE-2021-12345: apache 2.4.49 (low CVSS 5.3)",
            "severity": "low",
            "description": "Low risk issue",
            "location": "https://example.com",
            "section_id": "WSTG-CONF-01",
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "low"
    assert "CVE-2021-12345" in results[0]["vulnerability"]["name"]


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
    assert "Server software version disclosed" in cmd[2]


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
