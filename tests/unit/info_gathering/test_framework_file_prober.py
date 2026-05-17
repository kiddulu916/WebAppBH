"""Unit tests for FrameworkFileProber (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _session_with_status_map(status_by_substring: dict[str, int]) -> MagicMock:
    """Return mock aiohttp session where response status depends on URL substring."""
    def _get(url, *, timeout, allow_redirects):
        status = 404
        for substr, s in status_by_substring.items():
            if substr in url:
                status = s
                break
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp
    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=_get)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_path_matching_200():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({"wp-login.php": 200})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=20)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    cms = result.signals.get("cms", [])
    assert any(s["value"] == "WordPress" and "/wp-login.php" in s["path"] for s in cms)
    assert "/wp-login.php" in result.signals.get("_admin_paths", [])


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_403_counts_as_accessible():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({"/.env": 403})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=21)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    fw = result.signals.get("framework", [])
    assert any(s["value"] == "Laravel" and "/.env" in s["path"] for s in fw)


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_404_not_matched():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=22)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert result.signals.get("framework") == []
    assert result.signals.get("cms") == []
    assert result.signals.get("_admin_paths") == []
    assert result.signals.get("_info_file_paths") == []


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_info_file_recorded():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({"readme.html": 200})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=23)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert "/readme.html" in result.signals.get("_info_file_paths", [])


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_missing_kwargs_returns_error():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    result = await tool.execute(target_id=1)
    assert result.error is not None
