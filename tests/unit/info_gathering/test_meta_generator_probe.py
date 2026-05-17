"""Unit tests for MetaGeneratorProbe (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.fingerprint_aggregator import ProbeResult

_WP_HTML = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="https://api.w.org/" href="https://example.com/wp-json/" />
</head><body></body></html>"""

_DJANGO_HTML = """<html><body>
<form method="post">
<input type="hidden" name="csrfmiddlewaretoken" value="tok">
</form></body></html>"""

_RAILS_HTML = """<html><head>
<meta name="csrf-param" content="authenticity_token">
</head><body></body></html>"""

_DRUPAL_HTML = """<html><body>
<div data-drupal-messages-fallback class="hidden"></div>
</body></html>"""


def _mock_html_session(html: str) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.text = AsyncMock(return_value=html)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def test_wstg_page_parser_detects_wordpress_generator():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_WP_HTML)
    assert p.generator is not None and "WordPress" in p.generator
    assert p.has_wp_api_link is True


def test_wstg_page_parser_detects_django_csrftoken():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_DJANGO_HTML)
    assert p.has_django_csrf is True


def test_wstg_page_parser_detects_rails_csrf_param():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_RAILS_HTML)
    assert p.has_rails_csrf_param is True


def test_wstg_page_parser_detects_drupal_data_attr():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_DRUPAL_HTML)
    assert p.has_drupal_attr is True


@pytest.mark.asyncio
async def test_wstg_meta_generator_cms_detection_wordpress_with_version():
    from workers.info_gathering.tools.meta_generator_probe import MetaGeneratorProbe
    tool = MetaGeneratorProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_html_session(_WP_HTML)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=10)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    cms = result.signals.get("cms", [])
    wp = [s for s in cms if s["value"] == "WordPress"]
    assert len(wp) >= 1
    assert any(s.get("version") == "6.4.2" for s in wp)


@pytest.mark.asyncio
async def test_wstg_meta_generator_detects_django():
    from workers.info_gathering.tools.meta_generator_probe import MetaGeneratorProbe
    tool = MetaGeneratorProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_html_session(_DJANGO_HTML)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=11)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert any(s["value"] == "Django" for s in result.signals.get("framework", []))


@pytest.mark.asyncio
async def test_wstg_meta_generator_missing_kwargs_returns_error():
    from workers.info_gathering.tools.meta_generator_probe import MetaGeneratorProbe
    tool = MetaGeneratorProbe()
    result = await tool.execute(target_id=1)
    assert result.error is not None
