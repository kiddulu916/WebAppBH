"""Unit tests for CDNProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(headers: dict[str, str], org_text: str = "") -> MagicMock:
    """Mock aiohttp session: first call returns target headers, second returns org_text."""
    call_count = 0

    def _get(url, *, timeout, allow_redirects=True):
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        if "ipinfo.io" in url:
            mock_resp.status = 200
            mock_resp.text = AsyncMock(return_value=org_text)
        else:
            mock_resp.status = 200
            mock_resp.headers = headers
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp

    mock_sess = MagicMock()
    mock_sess.get = MagicMock(side_effect=_get)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_cdn_probe_detects_cloudflare_via_header():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    session = _make_session({"cf-ray": "abc123-LHR"})
    save_obs = AsyncMock(return_value=10)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    call_args = save_obs.call_args
    tech = call_args.kwargs.get("tech_stack") or call_args[1].get("tech_stack")
    assert tech["provider"] == "cloudflare"
    assert tech["detected"] is True


@pytest.mark.asyncio
async def test_wstg_cdn_probe_detects_fastly_via_header():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    session = _make_session({"x-served-by": "cache-lhr1234-LHR"})
    save_obs = AsyncMock(return_value=11)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["provider"] == "fastly"


@pytest.mark.asyncio
async def test_wstg_cdn_probe_no_cdn_detected():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    session = _make_session({"server": "nginx"}, org_text="AS12345 Some ISP")
    save_obs = AsyncMock(return_value=12)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch("asyncio.get_event_loop") as mock_loop, \
         patch.object(tool, "save_observation", new=save_obs):
        mock_loop.return_value.run_in_executor = AsyncMock(
            return_value=[(None, None, None, None, ("1.2.3.4", 0))]
        )
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is False
    assert tech["signals"] == []
    assert "1.2.3.4" in tech["ips"]


@pytest.mark.asyncio
async def test_wstg_cdn_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    result = await tool.execute(target_id=1)
    assert result is None
