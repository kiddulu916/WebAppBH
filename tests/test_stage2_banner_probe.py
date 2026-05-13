# tests/test_stage2_banner_probe.py
"""Tests for the Stage 2 BannerProbe."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.banner_probe import BannerProbe


class _FakeHeaders(dict):
    """Dict subclass that also satisfies aiohttp's ``getall(name, default)`` API."""

    def __init__(self, headers: dict, cookies: list[str]) -> None:
        super().__init__(headers)
        self._cookies = cookies

    def getall(self, name: str, default):
        if name == "Set-Cookie":
            return self._cookies
        return default


def _fake_session(headers: dict, status: int = 200, set_cookies: list[str] | None = None,
                  exception: Exception | None = None) -> MagicMock:
    """Build a ClientSession mock whose .get returns a response with these headers."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = _FakeHeaders(headers, set_cookies or [])

    resp_ctx = AsyncMock()
    resp_ctx.__aenter__ = AsyncMock(return_value=resp)
    resp_ctx.__aexit__ = AsyncMock(return_value=False)

    session = AsyncMock()
    if exception is not None:
        session.get = MagicMock(side_effect=exception)
    else:
        session.get = MagicMock(return_value=resp_ctx)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


class TestBannerProbe:
    @pytest.mark.anyio
    async def test_extracts_cloudflare_edge_and_express_framework(self):
        probe = BannerProbe()
        session = _fake_session(
            headers={"Server": "cloudflare", "X-Powered-By": "Express"},
            set_cookies=["__cf_bm=abc; path=/"],
        )
        with patch("workers.info_gathering.tools.banner_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=42):
            result = await probe.execute(
                target_id=1, asset_id=501, host="api.acme.com", intensity="low",
            )
        assert result.probe == "banner"
        assert result.obs_id == 42
        edge = result.signals["edge"]
        framework = result.signals["framework"]
        # Cloudflare via Server header + via __cf_bm cookie heuristic
        assert any(s["value"] == "Cloudflare" and s["w"] == 0.6 for s in edge)
        assert any(s["value"] == "Cloudflare" and s["w"] == 0.4 for s in edge)
        assert any(s["src"] == "banner.x_powered_by" and s["value"] == "Express"
                   for s in framework)
        assert result.signals["origin_server"] == []
        assert result.signals["_raw"]["obs_id"] == 42

    @pytest.mark.anyio
    async def test_origin_server_when_no_edge_match(self):
        probe = BannerProbe()
        session = _fake_session(
            headers={"Server": "nginx/1.25.0"},
        )
        with patch("workers.info_gathering.tools.banner_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=43):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.signals["edge"] == []
        assert any(s["value"] == "nginx" for s in result.signals["origin_server"])

    @pytest.mark.anyio
    async def test_returns_error_on_connection_failure(self):
        probe = BannerProbe()
        session = _fake_session(headers={}, exception=ConnectionError("refused"))
        with patch("workers.info_gathering.tools.banner_probe.aiohttp.ClientSession",
                   return_value=session):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error is not None
        assert result.obs_id is None

    @pytest.mark.anyio
    async def test_missing_kwargs_returns_error_result(self):
        probe = BannerProbe()
        result = await probe.execute(target_id=1, asset_id=None, host="a.com")
        assert result.error == "missing host or asset_id"

    @pytest.mark.anyio
    async def test_oversized_header_value_is_truncated(self):
        probe = BannerProbe()
        huge = "A" * 10_000
        session = _fake_session(headers={"Server": "nginx", "X-Big": huge})
        with patch("workers.info_gathering.tools.banner_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=99) as obs:
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        saved_headers = obs.call_args.kwargs["headers"]
        assert saved_headers["Server"] == "nginx"
        assert len(saved_headers["X-Big"]) < len(huge)
        assert saved_headers["X-Big"].endswith("...[truncated]")
        # _raw mirrors the truncated form (same dict reference)
        assert result.signals["_raw"]["headers"]["X-Big"].endswith("...[truncated]")
