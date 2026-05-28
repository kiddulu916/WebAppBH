"""Unit tests for engagement_fetcher — offline, no network calls."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "platform_pages"


def _html(filename: str) -> str:
    return (FIXTURE_DIR / filename).read_text(encoding="utf-8")


def test_search_bugcrowd_parses_candidates():
    from lib_webbh.platform_api.engagement_fetcher import _search_bugcrowd

    html = _html("bugcrowd_search.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    candidates = asyncio.run(
        _search_bugcrowd(mock_client, "acme")
    )
    assert len(candidates) == 1  # only bug_bounty type, not vdp
    assert candidates[0].handle == "acme-corp"
    assert candidates[0].platform == "bugcrowd"
    assert "bugcrowd.com/acme-corp" in candidates[0].url


def test_search_intigriti_parses_candidates():
    from lib_webbh.platform_api.engagement_fetcher import _search_intigriti

    html = _html("intigriti_search.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    candidates = asyncio.run(
        _search_intigriti(mock_client, "acme")
    )
    assert len(candidates) == 2
    assert candidates[0].handle == "acme-corp"
    assert candidates[0].platform == "intigriti"


def test_search_yeswehack_parses_candidates():
    from lib_webbh.platform_api.engagement_fetcher import _search_yeswehack

    html = _html("yeswehack_search.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    candidates = asyncio.run(
        _search_yeswehack(mock_client, "acme")
    )
    assert len(candidates) == 2
    assert candidates[0].handle == "acme-corp"
    assert candidates[0].platform == "yeswehack"


def test_fetch_bugcrowd_parses_scope():
    from lib_webbh.platform_api.engagement_fetcher import _fetch_bugcrowd, _parse_policy
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("bugcrowd_program.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    raw = asyncio.run(_fetch_bugcrowd(mock_client, "https://bugcrowd.com/acme-corp"))
    result = _parse_policy(raw, "bugcrowd", "acme-corp")

    assert result.program_name == "Acme Corp"
    assert len(result.in_scope) == 2
    assert len(result.out_of_scope_entries) == 1
    assert result.out_of_scope_entries[0].asset_value == "status.acme.com"
    assert result.rate_limit == 30
    assert "X-Bug-Bounty" in result.custom_headers
    assert result.custom_headers["X-Bug-Bounty"] == "hunter"

    # Verify eligible_for_bounty is read independently from in_scope
    wildcard_entry = next(e for e in result.in_scope if e.asset_value == "*.acme.com")
    api_entry = next(e for e in result.in_scope if e.asset_value == "api.acme.com")
    assert wildcard_entry.eligible_for_bounty is True
    assert api_entry.eligible_for_bounty is False  # in_scope=True but eligible_for_bounty=False


def test_fetch_intigriti_parses_scope():
    from lib_webbh.platform_api.engagement_fetcher import _fetch_intigriti, _parse_policy
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("intigriti_program.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    raw = asyncio.run(_fetch_intigriti(mock_client, "https://app.intigriti.com/programs/acme/acme-corp/scope"))
    result = _parse_policy(raw, "intigriti", "acme-corp")

    assert result.program_name == "Acme Corp"
    assert len(result.in_scope) == 2
    assert len(result.out_of_scope_entries) == 1
    assert result.rate_limit == 50


def test_fetch_yeswehack_parses_scope():
    from lib_webbh.platform_api.engagement_fetcher import _fetch_yeswehack, _parse_policy
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("yeswehack_program.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    raw = asyncio.run(_fetch_yeswehack(mock_client, "https://yeswehack.com/programs/acme-corp"))
    result = _parse_policy(raw, "yeswehack", "acme-corp")

    assert result.program_name == "Acme Corp"
    assert len(result.in_scope) == 1
    assert len(result.out_of_scope_entries) == 1
    assert result.rate_limit == 20


def test_parse_policy_empty_scope_adds_warning():
    from lib_webbh.platform_api.engagement_fetcher import _parse_policy

    raw = {"program_name": "Test", "in_scope_raw": [], "out_of_scope_raw": [],
           "guidelines": "", "_warnings": []}
    result = _parse_policy(raw, "bugcrowd", "test")
    assert any("fill manually" in w for w in result.parse_warnings)


def _make_result(guidelines: str = "", in_scope=None, out_of_scope=None):
    from lib_webbh.platform_api.engagement_fetcher import EngagementResult
    from lib_webbh.platform_api.base import ScopeEntry
    return EngagementResult(
        platform="bugcrowd",
        handle="test",
        program_name="Test Corp",
        in_scope=in_scope or [
            ScopeEntry("domain", "*.test.com", True),
            ScopeEntry("wildcard", "api.test.com", True),
        ],
        out_of_scope_entries=out_of_scope or [
            ScopeEntry("domain", "admin.test.com", False),
        ],
        rate_limit=30,
        custom_headers={"X-Test": "true"},
        guidelines=guidelines,
        stage_rules=[],
    )


def test_mapper_basic_prefill():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper
    mapper = EngagementMapper()
    result = _make_result()
    prefill = mapper.map(result)

    assert prefill.program_name == "Test Corp"
    assert "*.test.com" in prefill.in_scope
    assert "api.test.com" in prefill.in_scope
    assert "admin.test.com" in prefill.out_of_scope
    assert "*.test.com" in prefill.seed_targets
    assert prefill.rate_limit == 30
    assert prefill.custom_headers == {"X-Test": "true"}


def test_mapper_hard_disable_stage():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper
    mapper = EngagementMapper()
    result = _make_result(guidelines="No CSRF testing allowed.")
    prefill = mapper.map(result)

    assert "csrf" in prefill.conditional_stages
    rule = prefill.conditional_stages["csrf"]
    assert rule["out_of_scope"] is True
    assert rule["chain_exception"] is False


def test_mapper_chain_exception_stage():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper
    mapper = EngagementMapper()
    result = _make_result(
        guidelines="No CSRF unless proves critical impact. No SQL injection."
    )
    prefill = mapper.map(result)

    csrf_rule = prefill.conditional_stages.get("csrf", {})
    assert csrf_rule.get("out_of_scope") is True
    assert csrf_rule.get("chain_exception") is True

    sql_rule = prefill.conditional_stages.get("sql_injection", {})
    assert sql_rule.get("out_of_scope") is True
    assert sql_rule.get("chain_exception") is False


def test_mapper_rate_limit_defaults_to_50_when_none():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper, EngagementResult
    from lib_webbh.platform_api.base import ScopeEntry
    result = EngagementResult(
        platform="bugcrowd", handle="test", program_name="Test",
        in_scope=[ScopeEntry("domain", "x.com", True)],
        out_of_scope_entries=[], rate_limit=None,
        custom_headers={}, guidelines="", stage_rules=[],
    )
    prefill = EngagementMapper().map(result)
    assert prefill.rate_limit == 50


def test_mapper_chain_exception_upgrade_via_second_keyword():
    """If a stage has two keywords and the second one has an exception clause,
    the stage should be upgraded to chain_exception=True even if the first didn't have one."""
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper, ATTACK_KEYWORD_MAP

    # brute force and credential stuffing both map to lockout_mechanism
    # (verify this first)
    assert "lockout_mechanism" in ATTACK_KEYWORD_MAP
    kws = ATTACK_KEYWORD_MAP["lockout_mechanism"]
    assert len(kws) >= 2  # needs at least 2 keywords to test upgrade

    # First keyword triggers OOS without exception, second keyword's window has exception clause
    # lockout_mechanism keywords: ["brute force", "credential stuffing", "account lockout", "brute-force"]
    # Build text where "brute force" appears without exception, and "credential stuffing" appears with one
    guidelines = (
        "No brute force attacks. "
        "No credential stuffing unless demonstrates critical impact on user accounts."
    )

    mapper = EngagementMapper()
    result = _make_result(guidelines=guidelines)
    prefill = mapper.map(result)

    rule = prefill.conditional_stages.get("lockout_mechanism", {})
    assert rule.get("out_of_scope") is True
    # Should be True because "credential stuffing" keyword has exception clause in its window
    assert rule.get("chain_exception") is True


def test_mapper_keyword_map_coverage():
    """Every stage in PIPELINE_STAGES must appear in ATTACK_KEYWORD_MAP."""
    from lib_webbh.platform_api.engagement_fetcher import ATTACK_KEYWORD_MAP
    from lib_webbh.playbooks import PIPELINE_STAGES
    all_stages = [s for stages in PIPELINE_STAGES.values() for s in stages]
    missing = [s for s in all_stages if s not in ATTACK_KEYWORD_MAP]
    assert missing == [], f"Missing from ATTACK_KEYWORD_MAP: {missing}"
