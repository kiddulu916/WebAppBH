"""Unit tests for ServerlessProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(headers: dict[str, str]) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {k.lower(): v for k, v in headers.items()}
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_sess = MagicMock()
    mock_sess.get = MagicMock(return_value=mock_resp)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_serverless_probe_detects_aws_lambda():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    session = _make_session({"x-amz-request-id": "abc123", "x-amz-executed-version": "$LATEST"})
    save_obs = AsyncMock(return_value=30)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["platform"] == "aws_lambda"


@pytest.mark.asyncio
async def test_wstg_serverless_probe_detects_vercel():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    session = _make_session({"x-vercel-id": "iad1::abc123"})
    save_obs = AsyncMock(return_value=31)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["platform"] == "vercel"


@pytest.mark.asyncio
async def test_wstg_serverless_probe_no_serverless_detected():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    session = _make_session({"server": "nginx", "content-type": "text/html"})
    save_obs = AsyncMock(return_value=32)
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=save_obs):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = save_obs.call_args[1]["tech_stack"]
    assert tech["detected"] is False


@pytest.mark.asyncio
async def test_wstg_serverless_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    result = await tool.execute(target_id=1)
    assert result is None
