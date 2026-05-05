"""Tests for SecurityTrailsSearcher — optional SecurityTrails API integration."""

import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.securitytrails_searcher import SecurityTrailsSearcher


class TestSecurityTrailsSearcher:
    @pytest.mark.anyio
    async def test_skips_when_no_api_key(self):
        """Should return None when SECURITYTRAILS_API_KEY not set."""
        with patch.dict("os.environ", {}, clear=True):
            tool = SecurityTrailsSearcher()
            result = await tool.execute(
                target_id=1, domain="example.com", scope_manager=AsyncMock()
            )
        assert result is None

    @pytest.mark.anyio
    async def test_returns_stats_when_key_set(self):
        """Should return stats dict when API key is available."""
        with patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key"}):
            tool = SecurityTrailsSearcher()
            with patch("aiohttp.ClientSession") as mock_cls:
                mock_resp = AsyncMock()
                mock_resp.status = 200
                mock_resp.json = AsyncMock(return_value={
                    "current_dns": {"a": {"values": [{"ip": "1.2.3.4"}]}},
                    "subdomains": ["api", "dev"],
                    "records": [],
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
                     patch("workers.info_gathering.tools.securitytrails_searcher.asyncio.sleep", new_callable=AsyncMock):
                    result = await tool.execute(
                        target_id=1, domain="example.com", scope_manager=AsyncMock()
                    )
        assert isinstance(result, dict)
        assert result["found"] >= 1

    @pytest.mark.anyio
    async def test_no_domain_returns_zero(self):
        """Should return found=0 when no domain is provided."""
        with patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key"}):
            tool = SecurityTrailsSearcher()
            result = await tool.execute(target_id=1)
        assert result == {"found": 0}
