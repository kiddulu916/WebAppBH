"""Unit tests for the AccountEnumerator wrapper (WSTG-IDNT-04)."""
import json

import pytest

from workers.identity_mgmt.tools.account_enumerator import AccountEnumerator


@pytest.fixture
def tool():
    return AccountEnumerator()


class FakeTarget:
    target_value = "example.com"
    target_profile = {"account_enum": {"max_candidates": 2, "techniques": {"cms_wp": False}}}


class HttpTarget:
    target_value = "http://example.com"
    target_profile = None


def test_name_and_weight(tool):
    assert tool.name == "account_enumerator"


def test_build_command_invokes_module(tool):
    cmd = tool.build_command(FakeTarget())
    assert cmd[0] == "python3"
    assert cmd[1] == "-m"
    assert cmd[2] == "workers.identity_mgmt.tools.account_enum_probe"
    assert cmd[3] == "--config"


def test_build_command_embeds_https_base_url(tool):
    cmd = tool.build_command(FakeTarget())
    cfg = json.loads(cmd[4])
    assert cfg["base_url"] == "https://example.com"
    assert cfg["account_enum"]["max_candidates"] == 2
    assert cfg["account_enum"]["techniques"]["cms_wp"] is False


def test_build_command_preserves_http_scheme(tool):
    cfg = json.loads(tool.build_command(HttpTarget())[4])
    assert cfg["base_url"] == "http://example.com"
    assert cfg["account_enum"] == {}


def test_build_command_passes_token_when_present(tool):
    cfg = json.loads(tool.build_command(FakeTarget(), credentials={"token": "abc"})[4])
    assert cfg["token"] == "abc"


def test_parse_output_valid(tool):
    findings = [{"title": "x", "severity": "high", "description": "y", "data": {}}]
    assert tool.parse_output(json.dumps(findings)) == findings


def test_parse_output_malformed_returns_empty(tool):
    assert tool.parse_output("not json") == []


def test_parse_output_empty_returns_empty(tool):
    assert tool.parse_output("") == []
