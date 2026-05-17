"""Unit tests for WSTG 4.1.8 existing tool fixes (Task 1)."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.wappalyzer import Wappalyzer
from workers.info_gathering.tools.cookie_fingerprinter import CookieFingerprinter
from workers.info_gathering.tools.webanalyze import Webanalyze
from workers.info_gathering.fingerprint_aggregator import ProbeResult


@pytest.mark.asyncio
async def test_wstg_wappalyzer_returns_probe_result():
    tool = Wappalyzer()
    stdout = json.dumps({"technologies": [{"name": "WordPress"}, {"name": "PHP"}]})
    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=stdout)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=42)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.probe == "wappalyzer"
    assert result.obs_id == 42
    assert result.error is None
    assert any(s["value"] == "WordPress" for s in result.signals.get("cms", []))
    assert any(s["value"] == "PHP" for s in result.signals.get("language", []))


@pytest.mark.asyncio
async def test_wstg_wappalyzer_missing_kwargs_returns_error():
    tool = Wappalyzer()
    result = await tool.execute(target_id=1)
    assert isinstance(result, ProbeResult)
    assert result.error is not None


@pytest.mark.asyncio
async def test_wstg_cookie_fingerprinter_returns_probe_result():
    tool = CookieFingerprinter()
    mock_cookies = MagicMock()
    mock_cookies.keys.return_value = ["PHPSESSID", "wordpress_logged_in"]
    mock_resp = MagicMock()
    mock_resp.cookies = mock_cookies
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    with patch("aiohttp.ClientSession", return_value=mock_session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=7)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.probe == "cookie_framework"
    assert result.obs_id == 7
    assert any(s["value"] == "PHP" for s in result.signals.get("language", []))
    assert any(s["value"] == "WordPress" for s in result.signals.get("cms", []))


@pytest.mark.asyncio
async def test_wstg_webanalyze_returns_probe_result():
    tool = Webanalyze()
    stdout = json.dumps({"matches": [{"app_name": "Django"}, {"app_name": "Python"}]})
    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=stdout)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=55)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.probe == "webanalyze"
    assert result.obs_id == 55
    assert any(s["value"] == "Django" for s in result.signals.get("framework", []))
    assert any(s["value"] == "Python" for s in result.signals.get("language", []))
