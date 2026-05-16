"""Tests for EntryPointAggregator — WSTG-INFO-06."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.entry_point_aggregator import EntryPointAggregator


class TestExtractHeaderData:
    def _make_resp(self, status: int, headers: dict) -> MagicMock:
        """Build a fake aiohttp response with dict-backed headers."""
        resp = MagicMock()
        resp.status = status

        class FakeHeaders:
            def __init__(self, data):
                self._d = {k.lower(): v for k, v in data.items()}
                self._raw = data

            def items(self):
                return self._raw.items()

            def getall(self, key, default=None):
                val = self._raw.get(key) or self._raw.get(key.lower())
                if val is None:
                    return default or []
                return [val] if isinstance(val, str) else val

            def get(self, key, default=None):
                return self._raw.get(key) or self._raw.get(key.lower()) or default

            def __iter__(self):
                return iter(self._raw)

            def __contains__(self, item):
                return item in self._raw or item.lower() in self._d

        resp.headers = FakeHeaders(headers)
        return resp

    def test_captures_set_cookie(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"Set-Cookie": "session=abc; HttpOnly"})
        result = agg._extract_header_data(resp)
        assert "session=abc; HttpOnly" in result["set_cookie"]

    def test_captures_x_prefixed_custom_headers(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"X-Debug": "false", "Content-Type": "text/html"})
        result = agg._extract_header_data(resp)
        assert "X-Debug" in result["custom_headers"]

    def test_captures_server_header(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"Server": "nginx/1.21"})
        result = agg._extract_header_data(resp)
        assert "Server" in result["custom_headers"]

    def test_auth_required_true_on_401(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(401, {})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is True

    def test_auth_required_true_on_403(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(403, {})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is True

    def test_auth_required_true_on_www_authenticate_header(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"WWW-Authenticate": "Basic realm=x"})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is True

    def test_auth_required_false_on_200_no_auth_header(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"Content-Type": "text/html"})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is False

    def test_probe_key_present(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {})
        result = agg._extract_header_data(resp)
        assert result["_probe"] == "entry_point_aggregator"


class TestConsolidateQueryParams:
    @pytest.mark.anyio
    async def test_writes_parameter_rows_for_query_string(self):
        agg = EntryPointAggregator()
        asset = MagicMock()
        asset.id = 1
        asset.asset_value = "https://example.com/search?q=test&page=2"

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=None)
            sess.execute = AsyncMock(return_value=mock_result)

            written = await agg._consolidate_query_params(asset)

        assert written == 2
        assert sess.add.call_count == 2

    @pytest.mark.anyio
    async def test_skips_existing_parameters(self):
        agg = EntryPointAggregator()
        asset = MagicMock()
        asset.id = 1
        asset.asset_value = "https://example.com/search?q=test"

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=MagicMock())
            sess.execute = AsyncMock(return_value=mock_result)

            written = await agg._consolidate_query_params(asset)

        assert written == 0
        sess.add.assert_not_called()

    @pytest.mark.anyio
    async def test_url_with_no_query_string_returns_zero(self):
        agg = EntryPointAggregator()
        asset = MagicMock()
        asset.id = 1
        asset.asset_value = "https://example.com/about"
        written = await agg._consolidate_query_params(asset)
        assert written == 0


class TestEntryPointAggregatorExecute:
    @pytest.mark.anyio
    async def test_observation_written_per_asset(self):
        agg = EntryPointAggregator()

        fake_asset = MagicMock()
        fake_asset.id = 7
        fake_asset.asset_value = "https://example.com/login"
        fake_asset.source_tool = "katana"

        fake_obs_data = {
            "_probe": "entry_point_aggregator",
            "custom_headers": {"X-Frame-Options": "DENY"},
            "set_cookie": ["session=x"],
            "auth_required": False,
            "methods_allowed": [],
            "status_code": 200,
        }

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs, \
             patch.object(agg, "_capture_headers", new_callable=AsyncMock, return_value=fake_obs_data), \
             patch.object(agg, "_consolidate_query_params", new_callable=AsyncMock, return_value=0), \
             patch.object(agg, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_scalars = AsyncMock()
            mock_scalars.all = MagicMock(return_value=[fake_asset])
            mock_exec_result = AsyncMock()
            mock_exec_result.scalars = MagicMock(return_value=mock_scalars)
            sess.execute = AsyncMock(return_value=mock_exec_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await agg.execute(target_id=1)

        assert result["found"] == 1
        mock_obs.assert_called_once()
        assert mock_obs.call_args.kwargs["asset_id"] == 7

    @pytest.mark.anyio
    async def test_paramspider_assets_trigger_param_consolidation(self):
        agg = EntryPointAggregator()

        paramspider_asset = MagicMock()
        paramspider_asset.id = 3
        paramspider_asset.asset_value = "https://example.com/search?q=test"
        paramspider_asset.source_tool = "paramspider"

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs, \
             patch.object(agg, "_capture_headers", new_callable=AsyncMock, return_value=None), \
             patch.object(agg, "_consolidate_query_params", new_callable=AsyncMock, return_value=1) as mock_cons, \
             patch.object(agg, "save_observation", new_callable=AsyncMock, return_value=1), \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_scalars = AsyncMock()
            mock_scalars.all = MagicMock(return_value=[paramspider_asset])
            mock_exec_result = AsyncMock()
            mock_exec_result.scalars = MagicMock(return_value=mock_scalars)
            sess.execute = AsyncMock(return_value=mock_exec_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await agg.execute(target_id=1)

        mock_cons.assert_called_once_with(paramspider_asset)
        assert result["parameters"] == 1
