"""Unit tests for HeaderFrameworkProbe (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _mock_session(headers: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.headers = headers
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


@pytest.mark.asyncio
async def test_wstg_header_version_disclosure_aspnet_mvc():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session({"X-AspNetMvc-Version": "5.2"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=1)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    fw = result.signals.get("framework", [])
    assert any(s["value"] == "ASP.NET MVC" and s.get("version") == "5.2" for s in fw)


@pytest.mark.asyncio
async def test_wstg_header_version_disclosure_php():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session({"X-Powered-By": "PHP/8.1.12"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=2)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    lang = result.signals.get("language", [])
    assert any(s["value"] == "PHP" and s.get("version") == "8.1.12" for s in lang)


@pytest.mark.asyncio
async def test_wstg_header_drupal_x_generator():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session(
            {"X-Generator": "Drupal 9 (https://www.drupal.org)"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=3)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    cms = result.signals.get("cms", [])
    assert any(s["value"] == "Drupal" for s in cms)


@pytest.mark.asyncio
async def test_wstg_header_no_framework_headers_empty_signals():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session({"Server": "Apache"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=4)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert result.error is None
    assert result.signals.get("framework") == []
    assert result.signals.get("cms") == []
    assert result.signals.get("language") == []


@pytest.mark.asyncio
async def test_wstg_header_missing_kwargs_returns_error():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    result = await tool.execute(target_id=1)
    assert result.error is not None
