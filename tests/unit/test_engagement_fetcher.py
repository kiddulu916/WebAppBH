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
