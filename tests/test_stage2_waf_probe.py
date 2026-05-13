# tests/test_stage2_waf_probe.py
"""Tests for the Stage 2 WAFProbe."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests._stage2_helpers import fake_session as _fake_session_factory
from workers.info_gathering.tools.waf_probe import WAFProbe


def _fake_session(headers, cookies=None):
    return _fake_session_factory(headers=headers, cookies=cookies)


class TestWAFProbe:
    @pytest.mark.anyio
    async def test_low_intensity_passive_only_does_not_run_wafw00f(self):
        probe = WAFProbe()
        session = _fake_session({"CF-RAY": "abc123", "Server": "cloudflare"})
        with patch("workers.info_gathering.tools.waf_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "run_subprocess", new_callable=AsyncMock) as sub, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=7):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert sub.call_count == 0
        assert any(s["src"] == "waf_passive" and s["value"] == "Cloudflare"
                   for s in result.signals["waf"])

    @pytest.mark.anyio
    async def test_medium_intensity_runs_wafw00f_and_emits_active_signal(self):
        probe = WAFProbe()
        session = _fake_session({})  # no passive hits
        wafw00f_out = '{"detected":true,"firewall":"Cloudflare"}'
        with patch("workers.info_gathering.tools.waf_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=wafw00f_out) as sub, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=8):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="medium",
            )
        assert sub.call_count == 1
        assert any(s["src"] == "waf_active" and s["value"] == "Cloudflare"
                   for s in result.signals["waf"])

    @pytest.mark.anyio
    async def test_passive_cookie_matcher(self):
        probe = WAFProbe()
        session = _fake_session({}, cookies=["__cf_bm=abc; path=/"])
        with patch("workers.info_gathering.tools.waf_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=9):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert any(s["value"] == "Cloudflare" for s in result.signals["waf"])

    @pytest.mark.anyio
    async def test_no_waf_no_signals(self):
        probe = WAFProbe()
        session = _fake_session({"Server": "nginx"})
        with patch("workers.info_gathering.tools.waf_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=10):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.signals["waf"] == []

    @pytest.mark.anyio
    async def test_aiohttp_failure_returns_error_result(self):
        probe = WAFProbe()
        session = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.get = MagicMock(side_effect=ConnectionError("nope"))
        with patch("workers.info_gathering.tools.waf_probe.aiohttp.ClientSession",
                   return_value=session):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error is not None
