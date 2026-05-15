# tests/test_ct_log_searcher.py
"""Tests for CTLogSearcher — WSTG-INFO-04 CT log enumeration."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from workers.info_gathering.tools.ct_log_searcher import CTLogSearcher


@pytest.fixture
def tool():
    return CTLogSearcher()


@pytest.fixture
def mock_target():
    t = MagicMock()
    t.base_domain = "example.com"
    return t


class TestParseHostnames:
    def test_extracts_simple_subdomain(self, tool):
        data = [{"name_value": "sub.example.com"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "sub.example.com" in result

    def test_strips_wildcard_prefix(self, tool):
        data = [{"name_value": "*.example.com"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "example.com" in result
        assert "*.example.com" not in result

    def test_drops_out_of_scope_hostname(self, tool):
        data = [{"name_value": "other.org"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "other.org" not in result

    def test_handles_multiple_sans_per_record(self, tool):
        data = [{"name_value": "a.example.com\nb.example.com\nother.org"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "a.example.com" in result
        assert "b.example.com" in result
        assert "other.org" not in result

    def test_deduplicates_hostnames(self, tool):
        data = [
            {"name_value": "sub.example.com"},
            {"name_value": "sub.example.com"},
        ]
        result = tool._parse_hostnames(data, "example.com")
        assert result == {"sub.example.com"}

    def test_includes_base_domain_itself(self, tool):
        data = [{"name_value": "example.com"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "example.com" in result

    def test_empty_data_returns_empty_set(self, tool):
        assert tool._parse_hostnames([], "example.com") == set()


class TestExecute:
    @pytest.mark.anyio
    async def test_saves_discovered_hostnames(self, tool, mock_target):
        tool._fetch_crtsh = AsyncMock(return_value=[
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},
        ])
        saved = []

        async def fake_save_asset(target_id, asset_type, value, source, scope_manager=None, **kw):
            saved.append(value)
            return len(saved)

        tool.save_asset = fake_save_asset
        result = await tool.execute(1, target=mock_target, scope_manager=None)

        assert result["found"] == 2
        assert "api.example.com" in saved
        assert "example.com" in saved

    @pytest.mark.anyio
    async def test_skips_duplicate_assets(self, tool, mock_target):
        tool._fetch_crtsh = AsyncMock(return_value=[
            {"name_value": "sub.example.com"},
        ])
        # save_asset returns None when asset already exists
        tool.save_asset = AsyncMock(return_value=None)
        result = await tool.execute(1, target=mock_target, scope_manager=None)
        assert result["found"] == 0

    @pytest.mark.anyio
    async def test_returns_zero_when_fetch_returns_empty(self, tool, mock_target):
        tool._fetch_crtsh = AsyncMock(return_value=[])
        result = await tool.execute(1, target=mock_target, scope_manager=None)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_returns_zero_without_target(self, tool):
        result = await tool.execute(1)
        assert result == {"found": 0}


class TestFetchCrtsh:
    @pytest.mark.anyio
    async def test_returns_empty_list_on_non_200(self, tool):
        import aiohttp
        from unittest.mock import patch, MagicMock, AsyncMock

        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_get = MagicMock(return_value=mock_resp)

        mock_session = MagicMock()
        mock_session.get = mock_get
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("workers.info_gathering.tools.ct_log_searcher.aiohttp.ClientSession",
                   return_value=mock_session):
            result = await tool._fetch_crtsh("example.com")

        assert result == []

    @pytest.mark.anyio
    async def test_returns_empty_list_on_timeout(self, tool):
        import aiohttp
        from unittest.mock import patch

        with patch("workers.info_gathering.tools.ct_log_searcher.aiohttp.ClientSession",
                   side_effect=aiohttp.ClientConnectorError(None, OSError())):
            result = await tool._fetch_crtsh("example.com")

        assert result == []
