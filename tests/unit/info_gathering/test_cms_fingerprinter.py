"""Unit tests for CMSFingerprinter (WSTG 4.1.8 / merged INFO-09 scope)."""
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _make_session(responses: dict[str, tuple[int, bytes]]) -> MagicMock:
    """Mock aiohttp.ClientSession where responses map URL substring → (status, body)."""
    def _get(url, *, timeout, allow_redirects):
        body = b""
        status = 404
        for substr, (s, b) in responses.items():
            if substr in url:
                status = s
                body = b
                break
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.read = AsyncMock(return_value=body)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp
    mock_sess = MagicMock()
    mock_sess.get = MagicMock(side_effect=_get)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


_WP_BODY = b"fake-jquery-content-for-wordpress"
_WP_HASH = hashlib.md5(_WP_BODY).hexdigest()

_SMALL_DB = {
    "wordpress": {
        "probe_paths": ["/wp-login.php", "/wp-includes/js/jquery/jquery.min.js"],
        "versions": {
            "6.4.2": {"/wp-includes/js/jquery/jquery.min.js": _WP_HASH}
        },
    },
    "drupal": {
        "probe_paths": ["/core/CHANGELOG.txt"],
        "versions": {},
    },
}


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_detects_wordpress_with_version():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    session = _make_session({
        "/wp-login.php": (200, b"wp-login"),
        "/wp-includes/js/jquery/jquery.min.js": (200, _WP_BODY),
    })
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=_SMALL_DB), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=42)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    cms_signals = result.signals.get("cms", [])
    assert any(
        s["value"] == "WordPress" and s.get("version") == "6.4.2"
        for s in cms_signals
    )


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_detects_presence_without_version():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    # probe path returns 200 but with a body that doesn't match any known hash
    session = _make_session({"/wp-login.php": (200, b"not-matching-body")})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=_SMALL_DB), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=43)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    cms_signals = result.signals.get("cms", [])
    assert any(s["value"] == "WordPress" and s.get("version") == "unknown" for s in cms_signals)


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_no_cms_detected():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    session = _make_session({})  # all 404s
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=_SMALL_DB), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=44)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert result.signals.get("cms", []) == []


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_missing_kwargs_returns_error():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    result = await tool.execute(target_id=1)
    assert isinstance(result, ProbeResult)
    assert result.error is not None


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_confidence_score_uses_best_version():
    """Version with most hash matches should be selected."""
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    body_a = b"file-a-content"
    body_b = b"file-b-content"
    hash_a = hashlib.md5(body_a).hexdigest()
    hash_b = hashlib.md5(body_b).hexdigest()
    db = {
        "wordpress": {
            "probe_paths": ["/file-a.js", "/file-b.css"],
            "versions": {
                "6.4.2": {"/file-a.js": hash_a, "/file-b.css": hash_b},
                "6.3.1": {"/file-a.js": hash_a},
            },
        }
    }
    tool = CMSFingerprinter()
    session = _make_session({
        "/file-a.js": (200, body_a),
        "/file-b.css": (200, body_b),
    })
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=db), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=45)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    cms_signals = result.signals.get("cms", [])
    # 6.4.2 matches 2/2; 6.3.1 matches 1/1 — 6.4.2 wins on count
    assert any(s.get("version") == "6.4.2" for s in cms_signals)
