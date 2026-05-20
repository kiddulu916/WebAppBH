"""Unit tests for FilePermissionTester pure helper functions (WSTG-CONF-09)."""
from workers.config_mgmt.tools.file_permission_tester import (
    _SECTION_ID,
    _is_directory_listing,
    _classify_directory,
    _classify_sensitive_file,
)


def test_is_directory_listing_index_of():
    assert _is_directory_listing("<!DOCTYPE html><html><body>Index of /tmp</body></html>") is True


def test_is_directory_listing_parent_dir():
    assert _is_directory_listing("<a href=..>Parent Directory</a>") is True


def test_is_directory_listing_false():
    assert _is_directory_listing("<html><body><h1>Welcome</h1></body></html>") is False


def test_classify_directory_listing_high():
    url = "https://example.com/backup/"
    result = _classify_directory(url, 200, "Index of /backup")
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"
    assert result["vulnerability"]["location"] == url


def test_classify_directory_403():
    result = _classify_directory("https://example.com/admin/", 403, "")
    assert result is not None
    assert "observation" in result
    assert result["observation"]["type"] == "directory_access"
    assert result["observation"]["value"] == "access_denied"


def test_classify_directory_404():
    result = _classify_directory("https://example.com/secret/", 404, "")
    assert result is None


def test_classify_directory_200_no_listing():
    result = _classify_directory("https://example.com/app/", 200, "<html>Normal page</html>")
    assert result is None


def test_classify_sensitive_file_200_critical():
    result = _classify_sensitive_file("https://example.com/.env", ".env", 200, "critical")
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_sensitive_file_200_high():
    result = _classify_sensitive_file("https://example.com/web.config", "web.config", 200, "high")
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"


def test_classify_sensitive_file_200_medium():
    result = _classify_sensitive_file(
        "https://example.com/phpinfo.php", "phpinfo.php", 200, "medium"
    )
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "medium"


def test_classify_sensitive_file_200_low():
    result = _classify_sensitive_file(
        "https://example.com/composer.json", "composer.json", 200, "low"
    )
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "low"


def test_classify_sensitive_file_non_200():
    result = _classify_sensitive_file("https://example.com/.env", ".env", 404, "critical")
    assert result is None


def test_section_id_in_directory_vuln():
    result = _classify_directory("https://example.com/backup/", 200, "Index of /backup")
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-09"


def test_section_id_in_file_vuln():
    result = _classify_sensitive_file("https://example.com/.env", ".env", 200, "critical")
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-09"


def test_section_id_constant():
    assert _SECTION_ID == "WSTG-CONF-09"
