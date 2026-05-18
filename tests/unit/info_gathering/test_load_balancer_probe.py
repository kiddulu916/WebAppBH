"""Unit tests for LoadBalancerProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(cookie_headers: list[str]) -> MagicMock:
    """Return mock session whose HEAD responses yield given Set-Cookie values."""
    call_count = 0

    def _request(method, url, *, timeout, allow_redirects=False):
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        idx = min(call_count - 1, len(cookie_headers) - 1)
        hdr_val = cookie_headers[idx] if cookie_headers else ""
        mock_resp.headers.get = MagicMock(side_effect=lambda k, d=None: (
            hdr_val if k.lower() == "set-cookie" else d
        ))
        mock_resp.headers.getall = MagicMock(return_value=[hdr_val] if hdr_val else [])
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp

    mock_sess = MagicMock()
    mock_sess.request = MagicMock(side_effect=_request)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_detects_f5_bigip_cookie():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    session = _make_session(["BIGipServer~pool~443=1234567890.12345.0000; path=/"])
    save_obs = AsyncMock(return_value=20)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["vendor"] == "f5"


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_detects_aws_alb_cookie():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    session = _make_session(["AWSALB=abc123; Path=/; Max-Age=604800"])
    save_obs = AsyncMock(return_value=21)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["vendor"] == "aws_alb"


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_no_lb_detected():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    session = _make_session(["session=abc; path=/"])
    save_obs = AsyncMock(return_value=22)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is False


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_detects_via_header_variance():
    """Differing x-served-by values across requests indicate a LB pool."""
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    via_values = ["cache-node-1", "cache-node-2", "cache-node-3", "cache-node-1", "cache-node-2"]
    call_count = 0

    def _request(method, url, *, timeout, allow_redirects=False):
        nonlocal call_count
        idx = min(call_count, len(via_values) - 1)
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.headers.get = MagicMock(side_effect=lambda k, d=None: (
            via_values[idx] if k == "x-served-by" else d
        ))
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp

    mock_sess = MagicMock()
    mock_sess.request = MagicMock(side_effect=_request)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)

    save_obs = AsyncMock(return_value=23)
    with patch("aiohttp.ClientSession", return_value=mock_sess), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["served_by_variance"] > 1


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    result = await tool.execute(target_id=1)
    assert result is None
