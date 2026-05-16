"""Unit tests for Stage 7 — Map Execution Paths (WSTG-INFO-07)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.url_classifier import classify_url


# ---------------------------------------------------------------------------
# url_classifier additions
# ---------------------------------------------------------------------------

def test_url_classifier_ws_prefix_returns_websocket():
    assert classify_url("ws://example.com/socket") == "websocket"


def test_url_classifier_wss_prefix_returns_websocket():
    assert classify_url("wss://example.com/ws") == "websocket"


def test_url_classifier_api_v1_path_returns_api_endpoint():
    assert classify_url("https://example.com/api/v1/users") == "api_endpoint"


def test_url_classifier_graphql_returns_api_endpoint():
    assert classify_url("https://example.com/graphql") == "api_endpoint"


def test_url_classifier_rest_path_returns_api_endpoint():
    assert classify_url("https://example.com/rest/items") == "api_endpoint"


def test_url_classifier_ws_check_runs_before_path_rules():
    # A ws:// URL with /api/ in the path should still be websocket, not api_endpoint
    assert classify_url("wss://example.com/api/ws") == "websocket"


# ---------------------------------------------------------------------------
# FormMapper URL cap removal
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_form_mapper_processes_more_than_20_urls():
    """FormMapper must not silently cap at 20 URLs."""
    from workers.info_gathering.tools.form_mapper import FormMapper

    tool = FormMapper()

    # 25 pre-existing URL assets in the DB mock (url, asset_id) pairs
    url_assets = [(f"https://example.com/page{i}", i + 1) for i in range(25)]

    fetched_urls: list[str] = []

    async def mock_fetch_html(url):
        fetched_urls.append(url)
        # Return minimal HTML with a form so the tool records observations
        return '<form action="/submit" method="POST"><input name="email"></form>'

    # Patch DB query to return 25 URL assets
    from contextlib import asynccontextmanager
    from unittest.mock import MagicMock

    mock_result = MagicMock()
    mock_result.all.return_value = url_assets
    mock_execute = AsyncMock(return_value=mock_result)
    mock_session = MagicMock()
    mock_session.execute = mock_execute
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    target = MagicMock(base_domain="example.com")

    with patch("workers.info_gathering.tools.form_mapper.get_session", mock_get_session), \
         patch.object(tool, "_fetch_html", side_effect=mock_fetch_html), \
         patch.object(tool, "save_observation", new=AsyncMock()), \
         patch.object(tool, "_write_parameters", new=AsyncMock()):
        await tool.execute(target_id=1, target=target)

    # Should have processed all 26 URLs (25 from DB + 1 base domain prepended)
    assert len(fetched_urls) > 20, (
        f"FormMapper capped at {len(fetched_urls)} URLs — cap was not removed"
    )
