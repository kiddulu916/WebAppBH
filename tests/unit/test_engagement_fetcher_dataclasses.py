import pytest
from lib_webbh.platform_api.engagement_fetcher import (
    ProgramCandidate,
    StageRule,
    EngagementResult,
    CampaignFormPrefill,
    ATTACK_KEYWORD_MAP,
    _EXCEPTION_RE,
    _RATE_LIMIT_RE,
    _CUSTOM_HEADER_RE,
)
from lib_webbh.platform_api.base import ScopeEntry
from lib_webbh.playbooks import PIPELINE_STAGES


def test_program_candidate_fields():
    pc = ProgramCandidate(name="Acme Corp", handle="acme", url="https://bugcrowd.com/acme", platform="bugcrowd")
    assert pc.name == "Acme Corp"
    assert pc.platform == "bugcrowd"


def test_stage_rule_fields():
    sr = StageRule(stage_name="csrf", out_of_scope=True, chain_exception=True, reason="no CSRF unless critical")
    assert sr.out_of_scope is True
    assert sr.chain_exception is True


def test_engagement_result_defaults():
    er = EngagementResult(
        platform="bugcrowd",
        handle="acme",
        program_name="Acme",
        in_scope=[],
        out_of_scope_entries=[],
        rate_limit=None,
        custom_headers={},
        guidelines="",
        stage_rules=[],
    )
    assert er.parse_warnings == []
    assert er.rate_limit is None


def test_campaign_form_prefill_defaults():
    prefill = CampaignFormPrefill(
        program_name="Acme",
        seed_targets=[],
        in_scope=[],
        out_of_scope=[],
        rate_limit=50,
        custom_headers={},
        guidelines="",
        conditional_stages={},
    )
    assert prefill.parse_warnings == []
    assert prefill.rate_limit == 50


def test_attack_keyword_map_all_stages_present():
    all_stages = {stage for stages in PIPELINE_STAGES.values() for stage in stages}
    for stage in all_stages:
        assert stage in ATTACK_KEYWORD_MAP, f"Stage '{stage}' missing from ATTACK_KEYWORD_MAP"


def test_exception_re_matches_critical_impact():
    text = "no csrf unless proves critical impact on the application"
    assert _EXCEPTION_RE.search(text) is not None


def test_exception_re_matches_deeper_impact():
    text = "not in scope unless can demonstrate deeper impact"
    assert _EXCEPTION_RE.search(text) is not None


def test_exception_re_no_match_plain_oos():
    text = "csrf is not accepted"
    assert _EXCEPTION_RE.search(text) is None


def test_rate_limit_re_per_second():
    text = "please limit to 50 requests per second"
    m = _RATE_LIMIT_RE.search(text)
    assert m is not None
    assert m.group(1) == "50"


def test_rate_limit_re_per_minute():
    text = "100 req/min max"
    m = _RATE_LIMIT_RE.search(text)
    assert m is not None
    assert m.group(1) == "100"


def test_custom_header_re():
    text = "Please include X-Bug-Bounty: hunter-name in all requests"
    m = _CUSTOM_HEADER_RE.search(text)
    assert m is not None
    assert m.group(1) == "X-Bug-Bounty"
