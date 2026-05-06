"""Tests for stackable rate limiter rules and RateLimiter class."""

import pytest
from unittest.mock import AsyncMock, patch
from lib_webbh.rate_limiter import RateLimiter, RateRule, parse_rate_rule


class TestParseRateRule:
    def test_req_per_second(self):
        rule = parse_rate_rule({"amount": 50, "unit": "req/s"})
        assert rule.amount == 50
        assert rule.window_seconds == 1
        assert rule.rule_type == "request"

    def test_req_per_custom_window(self):
        rule = parse_rate_rule({"amount": 100, "unit": "req/5s"})
        assert rule.amount == 100
        assert rule.window_seconds == 5

    def test_req_per_minute(self):
        rule = parse_rate_rule({"amount": 500, "unit": "req/min"})
        assert rule.window_seconds == 60

    def test_req_per_hour(self):
        rule = parse_rate_rule({"amount": 10000, "unit": "req/hr"})
        assert rule.window_seconds == 3600

    def test_req_per_day(self):
        rule = parse_rate_rule({"amount": 50000, "unit": "req/day"})
        assert rule.window_seconds == 86400

    def test_bytes_per_second(self):
        rule = parse_rate_rule({"amount": 500, "unit": "bytes/s"})
        assert rule.amount == 500
        assert rule.rule_type == "bandwidth"

    def test_kb_per_second(self):
        rule = parse_rate_rule({"amount": 100, "unit": "KB/s"})
        assert rule.amount == 100 * 1024

    def test_mb_per_second(self):
        rule = parse_rate_rule({"amount": 5, "unit": "MB/s"})
        assert rule.amount == 5 * 1024 * 1024

    def test_mb_per_custom_window(self):
        rule = parse_rate_rule({"amount": 10, "unit": "MB/30s"})
        assert rule.amount == 10 * 1024 * 1024
        assert rule.window_seconds == 30

    def test_invalid_unit_raises(self):
        with pytest.raises(ValueError):
            parse_rate_rule({"amount": 50, "unit": "invalid"})


class TestRateLimiter:
    @pytest.mark.anyio
    async def test_allows_within_limit(self):
        """Requests within the limit should proceed immediately."""
        mock_redis = AsyncMock()
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[0, 5])  # 5 requests in window
        mock_redis.pipeline = lambda: mock_pipe
        mock_redis.zadd = AsyncMock()
        mock_redis.expire = AsyncMock()

        rules = [RateRule(amount=50, window_seconds=1, rule_type="request")]
        limiter = RateLimiter(mock_redis, campaign_id=1, rules=rules)

        with patch("lib_webbh.rate_limiter.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.acquire()
            mock_sleep.assert_not_called()

    @pytest.mark.anyio
    async def test_blocks_when_limit_exceeded(self):
        """Requests exceeding the limit should wait."""
        call_count = 0

        mock_redis = AsyncMock()
        mock_pipe = AsyncMock()

        async def mock_execute():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return [0, 50]  # At limit
            return [0, 10]  # Below limit after waiting

        mock_pipe.execute = mock_execute
        mock_redis.pipeline = lambda: mock_pipe
        mock_redis.zadd = AsyncMock()
        mock_redis.expire = AsyncMock()

        rules = [RateRule(amount=50, window_seconds=1, rule_type="request")]
        limiter = RateLimiter(mock_redis, campaign_id=1, rules=rules)

        with patch("lib_webbh.rate_limiter.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.acquire()
            mock_sleep.assert_called()

    @pytest.mark.anyio
    async def test_multiple_rules_checked(self):
        """When multiple rules exist, all are checked."""
        mock_redis = AsyncMock()
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[0, 5])
        mock_redis.pipeline = lambda: mock_pipe
        mock_redis.zadd = AsyncMock()
        mock_redis.expire = AsyncMock()

        rules = [
            RateRule(amount=50, window_seconds=1, rule_type="request"),
            RateRule(amount=1000, window_seconds=60, rule_type="request"),
        ]
        limiter = RateLimiter(mock_redis, campaign_id=1, rules=rules)

        # Should succeed — both rules allow it
        with patch("lib_webbh.rate_limiter.asyncio.sleep", new_callable=AsyncMock):
            await limiter.acquire()
            # zadd should be called for each rule
            assert mock_redis.zadd.call_count == 2
