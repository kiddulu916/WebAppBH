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
