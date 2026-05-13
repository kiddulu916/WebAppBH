# tests/test_stage2_method_probe.py
"""Tests for the Stage 2 MethodProbe."""
from unittest.mock import AsyncMock, patch

import pytest

from workers.info_gathering.tools.method_probe import (
    HIGH_METHODS,
    LOW_METHODS,
    MED_METHODS,
    MethodProbe,
)


def _patch_session() -> AsyncMock:
    """Build a ``ClientSession`` mock that supports ``async with``."""
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


class TestMethodProbe:
    @pytest.mark.anyio
    async def test_low_intensity_only_sends_low_methods(self):
        probe = MethodProbe()
        session = _patch_session()
        with patch("workers.info_gathering.tools.method_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "_send_method",
                          new_callable=AsyncMock,
                          return_value={"status": 200, "body_len": 0, "allow": "", "server": ""}) as send, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=3):
            await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        sent = [c.args[1] for c in send.call_args_list]
        assert sent == LOW_METHODS
        # No medium/high verbs leaked
        for m in MED_METHODS + HIGH_METHODS:
            assert m not in sent

    @pytest.mark.anyio
    async def test_medium_intensity_adds_propfind_and_trace(self):
        probe = MethodProbe()
        session = _patch_session()
        with patch("workers.info_gathering.tools.method_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "_send_method",
                          new_callable=AsyncMock,
                          return_value={"status": 405, "body_len": 0, "allow": "", "server": ""}) as send, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=4):
            await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="medium",
            )
        sent = [c.args[1] for c in send.call_args_list]
        assert "PROPFIND" in sent
        assert "TRACE" in sent
        for m in HIGH_METHODS:
            assert m not in sent

    @pytest.mark.anyio
    async def test_high_intensity_includes_garbage_verb(self):
        probe = MethodProbe()
        session = _patch_session()
        with patch("workers.info_gathering.tools.method_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "_send_method",
                          new_callable=AsyncMock,
                          return_value={"status": 405, "body_len": 0, "allow": "", "server": ""}) as send, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=5):
            await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="high",
            )
        sent = [c.args[1] for c in send.call_args_list]
        assert "ASDF" in sent

    @pytest.mark.anyio
    async def test_iis_signal_when_options_allow_includes_propfind(self):
        probe = MethodProbe()
        session = _patch_session()

        async def fake_send(_session, method, _url):
            if method == "OPTIONS":
                return {"status": 200, "body_len": 0,
                        "allow": "GET, HEAD, POST, OPTIONS, PROPFIND", "server": "IIS"}
            return {"status": 200, "body_len": 0, "allow": "", "server": ""}

        with patch("workers.info_gathering.tools.method_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "_send_method",
                          new_callable=AsyncMock, side_effect=fake_send), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=6):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert any(s["value"] == "IIS" for s in result.signals["origin_server"])

    @pytest.mark.anyio
    async def test_missing_kwargs_returns_error_result(self):
        probe = MethodProbe()
        result = await probe.execute(target_id=1, asset_id=None, host="a.com")
        assert result.error == "missing host or asset_id"
