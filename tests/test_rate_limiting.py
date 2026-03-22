import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import tests._patch_logger  # noqa

pytestmark = pytest.mark.anyio


async def test_rate_limit_allows_normal_traffic():
    """Rate limiter should allow requests under the limit."""
    from orchestrator.rate_limit import rate_limit_check

    request = MagicMock()
    request.method = "GET"
    request.client.host = "127.0.0.1"

    mock_pipe = MagicMock()
    mock_pipe.zremrangebyscore.return_value = mock_pipe
    mock_pipe.zadd.return_value = mock_pipe
    mock_pipe.zcard.return_value = mock_pipe
    mock_pipe.expire.return_value = mock_pipe
    mock_pipe.execute = AsyncMock(return_value=[None, None, 5, None])  # 5 requests

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    with patch("orchestrator.rate_limit.get_redis", return_value=mock_redis):
        await rate_limit_check(request)  # Should not raise


async def test_rate_limit_blocks_excess():
    """Rate limiter should raise 429 when limit exceeded."""
    from orchestrator.rate_limit import rate_limit_check
    from fastapi import HTTPException

    request = MagicMock()
    request.method = "POST"
    request.client.host = "127.0.0.1"

    mock_pipe = MagicMock()
    mock_pipe.zremrangebyscore.return_value = mock_pipe
    mock_pipe.zadd.return_value = mock_pipe
    mock_pipe.zcard.return_value = mock_pipe
    mock_pipe.expire.return_value = mock_pipe
    mock_pipe.execute = AsyncMock(return_value=[None, None, 999, None])  # Way over limit

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    with patch("orchestrator.rate_limit.get_redis", return_value=mock_redis):
        with pytest.raises(HTTPException) as exc_info:
            await rate_limit_check(request)
        assert exc_info.value.status_code == 429


async def test_rate_limit_skips_on_redis_error():
    """If Redis is unavailable, skip rate limiting gracefully."""
    from orchestrator.rate_limit import rate_limit_check

    request = MagicMock()
    request.method = "GET"
    request.client.host = "127.0.0.1"

    with patch("orchestrator.rate_limit.get_redis", side_effect=Exception("Redis down")):
        await rate_limit_check(request)  # Should not raise
