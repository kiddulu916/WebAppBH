"""Tests for CensysSearcher — optional Censys API integration."""

import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.censys_searcher import CensysSearcher


class TestCensysSearcher:
    @pytest.mark.anyio
    async def test_skips_when_no_api_keys(self):
        """Should return None when CENSYS_API_ID or CENSYS_API_SECRET not set."""
        with patch.dict("os.environ", {}, clear=True):
            tool = CensysSearcher()
            result = await tool.execute(
                target_id=1, domain="example.com", scope_manager=AsyncMock()
            )
        assert result is None

    @pytest.mark.anyio
    async def test_skips_when_only_id_set(self):
        """Should return None when only API ID is set."""
        with patch.dict("os.environ", {"CENSYS_API_ID": "test-id"}, clear=True):
            tool = CensysSearcher()
            result = await tool.execute(
                target_id=1, domain="example.com", scope_manager=AsyncMock()
            )
        assert result is None

    @pytest.mark.anyio
    async def test_returns_stats_when_keys_set(self):
        """Should return stats dict when both API keys are available."""
        with patch.dict("os.environ", {
            "CENSYS_API_ID": "test-id",
            "CENSYS_API_SECRET": "test-secret",
        }):
            tool = CensysSearcher()
            with patch("aiohttp.ClientSession") as mock_cls:
                mock_resp = AsyncMock()
                mock_resp.status = 200
                mock_resp.json = AsyncMock(return_value={
                    "result": {"hits": [{"ip": "1.2.3.4", "services": []}]}
                })
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_session = AsyncMock()
                mock_session.get = lambda *a, **kw: mock_ctx
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                mock_cls.return_value = mock_session

                with patch.object(tool, "save_asset", new_callable=AsyncMock, return_value=1), \
                     patch.object(tool, "save_observation", new_callable=AsyncMock), \
                     patch("workers.info_gathering.tools.censys_searcher.asyncio.sleep", new_callable=AsyncMock):
                    result = await tool.execute(
                        target_id=1, domain="example.com", scope_manager=AsyncMock()
                    )
        assert isinstance(result, dict)
        assert result["found"] >= 1
