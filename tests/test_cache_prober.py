"""Tests for CacheProber — archive.ph snapshot discovery."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from workers.info_gathering.tools.cache_prober import CacheProber


class TestCacheProber:
    @pytest.mark.anyio
    async def test_returns_stats_dict(self):
        """Execute should return stats with found count."""
        prober = CacheProber()
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.text = AsyncMock(return_value='<a href="https://example.com/page">link</a>')
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_session = AsyncMock()
            mock_session.get = MagicMock(return_value=mock_ctx)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            with patch.object(prober, "save_asset", new_callable=AsyncMock, return_value=1):
                result = await prober.execute(
                    target_id=1, domain="example.com", scope_manager=AsyncMock()
                )
        assert isinstance(result, dict)
        assert "found" in result

    @pytest.mark.anyio
    async def test_no_domain_returns_zero(self):
        """Should return found=0 when no domain is provided."""
        prober = CacheProber()
        result = await prober.execute(target_id=1)
        assert result == {"found": 0}

    def test_extract_urls_filters_target_domain(self):
        """Should only extract URLs belonging to the target domain."""
        html = '''
        <a href="https://example.com/admin">Admin</a>
        <a href="https://other.com/page">Other</a>
        <a href="https://sub.example.com/api">API</a>
        <a href="https://archive.ph/abc">Archive link</a>
        '''
        urls = CacheProber._extract_urls(html, "example.com")
        assert "https://example.com/admin" in urls
        assert "https://sub.example.com/api" in urls
        assert "https://other.com/page" not in urls
        assert all("archive.ph" not in u for u in urls)

    def test_extract_urls_empty_html(self):
        """Should return empty list for empty HTML."""
        urls = CacheProber._extract_urls("", "example.com")
        assert urls == []
