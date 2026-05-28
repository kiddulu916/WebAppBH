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
