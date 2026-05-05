"""Tests for ArchiveProber cached content retrieval."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from workers.info_gathering.tools.archive_prober import (
    ArchiveProber,
    SENSITIVE_EXTENSIONS,
    MAX_CACHED_FETCHES,
)


class TestArchiveProberSensitiveExtensions:
    def test_sensitive_extensions_include_common_types(self):
        assert ".env" in SENSITIVE_EXTENSIONS
        assert ".sql" in SENSITIVE_EXTENSIONS
        assert ".bak" in SENSITIVE_EXTENSIONS
        assert ".key" in SENSITIVE_EXTENSIONS
        assert ".pem" in SENSITIVE_EXTENSIONS

    def test_max_cached_fetches_is_20(self):
        assert MAX_CACHED_FETCHES == 20


class TestArchiveProber:
    @pytest.mark.anyio
    async def test_returns_stats_dict(self):
        """Execute should return stats with found count."""
        prober = ArchiveProber()
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=[
                ["timestamp", "original", "statuscode"],  # header
                ["20240101000000", "https://example.com/page", "200"],
            ])
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
        prober = ArchiveProber()
        result = await prober.execute(target_id=1)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_fetch_cached_content_returns_text(self):
        """_fetch_cached_content should return text on success."""
        prober = ArchiveProber()
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.text = AsyncMock(return_value="SECRET=leaked_password_123")
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_session = AsyncMock()
            mock_session.get = MagicMock(return_value=mock_ctx)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            content = await prober._fetch_cached_content(
                "https://example.com/.env", "20240101000000"
            )
        assert content == "SECRET=leaked_password_123"

    @pytest.mark.anyio
    async def test_fetch_cached_content_returns_none_on_failure(self):
        """_fetch_cached_content should return None on HTTP error."""
        prober = ArchiveProber()
        import aiohttp
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = AsyncMock()
            mock_session.get = MagicMock(side_effect=aiohttp.ClientError("timeout"))
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            content = await prober._fetch_cached_content(
                "https://example.com/.env", "20240101000000"
            )
        assert content is None
