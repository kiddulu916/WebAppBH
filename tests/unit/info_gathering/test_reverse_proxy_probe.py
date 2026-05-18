"""Unit tests for ReverseProxyProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(headers: dict[str, str]) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = headers  # raw case; production code lowercases via resp.headers.items()
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_sess = MagicMock()
    mock_sess.get = MagicMock(return_value=mock_resp)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_detects_varnish():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    session = _make_session({"Server": "Apache", "X-Varnish": "123456789"})
    save_obs = AsyncMock(return_value=40)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["proxy_type"] == "varnish"
    assert "x-varnish" in tech["signals"]


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_detects_via_mismatch():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    session = _make_session({"Server": "nginx", "Via": "1.1 varnish (Varnish/7.0)"})
    save_obs = AsyncMock(return_value=41)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert "via" in tech["signals"]


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_no_proxy_detected():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    session = _make_session({"Server": "nginx", "Content-Type": "text/html"})
    save_obs = AsyncMock(return_value=42)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is False
    assert tech["proxy_type"] == "none"
    assert tech["signals"] == []


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    result = await tool.execute(target_id=1)
    assert result is None
