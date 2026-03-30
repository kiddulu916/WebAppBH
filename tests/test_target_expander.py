# tests/test_target_expander.py
import pytest

pytestmark = pytest.mark.anyio


def test_score_priority_high_value_prefix():
    from orchestrator.target_expander import TargetExpander

    expander = TargetExpander()
    score = expander._score_priority(
        {"hostname": "api.target.com", "ips": {"1.2.3.4"}, "sources": ["subfinder", "amass", "httpx"]},
        None,
    )
    # api prefix (+15) + unique IP (+20) + 3 sources (+10) + base 50 = 95
    assert score >= 85


def test_score_priority_cdn_low():
    from orchestrator.target_expander import TargetExpander

    expander = TargetExpander()
    score = expander._score_priority(
        {"hostname": "cdn.target.com", "ips": set(), "sources": ["subfinder"]},
        None,
    )
    # cdn prefix (-15) + single source (-5) + base 50 = 30
    assert score <= 40


def test_score_priority_wildcard():
    from orchestrator.target_expander import TargetExpander

    expander = TargetExpander()
    score = expander._score_priority(
        {"hostname": "wild.target.com", "ips": set(), "sources": ["subfinder"], "wildcard": True},
        None,
    )
    # wildcard (-30) + single source (-5) + base 50 = 15
    assert score <= 25


def test_deduplicate_removes_duplicates():
    from orchestrator.target_expander import TargetExpander
    from unittest.mock import MagicMock

    expander = TargetExpander()

    assets = [
        MagicMock(asset_type="subdomain", data={"hostname": "api.target.com", "ip": "1.1.1.1"}, source_tool="subfinder"),
        MagicMock(asset_type="subdomain", data={"hostname": "api.target.com", "ip": "1.1.1.1"}, source_tool="amass"),
        MagicMock(asset_type="subdomain", data={"hostname": "web.target.com", "ip": "2.2.2.2"}, source_tool="subfinder"),
    ]

    unique = expander._deduplicate(assets)
    hostnames = [h["hostname"] for h in unique]
    assert len(hostnames) == 2
    assert "api.target.com" in hostnames
    assert "web.target.com" in hostnames