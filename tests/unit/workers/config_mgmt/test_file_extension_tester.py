"""Unit tests for WSTG-CONF-03 FileExtensionTester."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from workers.config_mgmt.tools.file_extension_tester import (
    FileExtensionTester,
    _generate_short_name,
)


# ── _generate_short_name ──────────────────────────────────────────────────────

def test_generate_short_name_standard():
    assert _generate_short_name("/webconfig") == "WEBCON"


def test_generate_short_name_short_path_returns_empty():
    assert _generate_short_name("/ab") == ""


def test_generate_short_name_root_returns_empty():
    assert _generate_short_name("/") == ""


def test_generate_short_name_strips_special_chars():
    # hyphens and dots are removed; only alphanumeric kept, then truncated to 6
    assert _generate_short_name("/my-config.php") == "MYCONF"


def test_generate_short_name_exact_six_chars():
    assert _generate_short_name("/backup") == "BACKUP"


# ── _analyze_response helpers ─────────────────────────────────────────────────

def _mock_resp(body: str, content_type: str = "text/html") -> MagicMock:
    resp = MagicMock()
    resp.text = body
    resp.headers = {"content-type": content_type}
    return resp


# ── _analyze_response ─────────────────────────────────────────────────────────

def test_analyze_response_database_is_critical():
    result = FileExtensionTester._analyze_response(
        "http://t/db.sql", "/db", ".sql", "database",
        _mock_resp("-- SQL dump")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-03"


def test_analyze_response_credentials_upgrade_to_critical():
    result = FileExtensionTester._analyze_response(
        "http://t/config.bak", "/config", ".bak", "backup",
        _mock_resp("password=hunter2")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_response_never_serve_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/app.asa", "/app", ".asa", "never_serve",
        _mock_resp("some content")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_source_code_with_php_syntax_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/index.php", "/index", ".php", "source_code",
        _mock_resp("<?php echo 'hello'; ?>")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_source_code_plain_text_content_type_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/index.php", "/index", ".php", "source_code",
        _mock_resp("some code", content_type="text/plain")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_source_code_html_no_syntax_is_none():
    # App is executing the PHP (returns HTML) — not a disclosure finding
    result = FileExtensionTester._analyze_response(
        "http://t/index.php", "/index", ".php", "source_code",
        _mock_resp("<html><body>Welcome</body></html>", content_type="text/html")
    )
    assert result is None


def test_analyze_response_document_no_creds_is_none():
    result = FileExtensionTester._analyze_response(
        "http://t/readme.txt", "/readme", ".txt", "document",
        _mock_resp("This is the readme file.")
    )
    assert result is None


def test_analyze_response_document_with_creds_is_critical():
    result = FileExtensionTester._analyze_response(
        "http://t/notes.txt", "/notes", ".txt", "document",
        _mock_resp("admin password=letmein")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_response_archive_is_high():
    result = FileExtensionTester._analyze_response(
        "http://t/backup.zip", "/backup", ".zip", "archive",
        _mock_resp("PK binary data")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


def test_analyze_response_config_is_medium():
    result = FileExtensionTester._analyze_response(
        "http://t/app.yml", "/app", ".yml", "configuration",
        _mock_resp("app:\n  name: myapp")
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "medium"


# ── _fetch_path_stems ─────────────────────────────────────────────────────────

async def test_fetch_path_stems_extracts_unique_stems():
    tester = FileExtensionTester()
    mock_assets = [
        MagicMock(asset_value="https://example.com/admin/login.php"),
        MagicMock(asset_value="https://example.com/api/v1/users.json"),
        MagicMock(asset_value="https://example.com/admin/login.php"),  # duplicate
    ]
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = mock_assets
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    stems = await tester._fetch_path_stems(mock_session, target_id=1)

    assert "/admin/login" in stems
    assert "/api/v1/users" in stems
    assert stems.count("/admin/login") == 1  # deduplicated


async def test_fetch_path_stems_returns_empty_on_no_assets():
    tester = FileExtensionTester()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    stems = await tester._fetch_path_stems(mock_session, target_id=1)
    assert stems == []


# ── _is_iis_detected ──────────────────────────────────────────────────────────

async def test_is_iis_detected_true_when_asset_exists():
    tester = FileExtensionTester()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = MagicMock()  # non-None = found

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    assert await tester._is_iis_detected(mock_session, target_id=1) is True


async def test_is_iis_detected_false_when_no_asset():
    tester = FileExtensionTester()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    assert await tester._is_iis_detected(mock_session, target_id=1) is False
