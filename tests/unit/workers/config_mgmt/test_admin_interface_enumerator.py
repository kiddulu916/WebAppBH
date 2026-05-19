"""Unit tests for AdminInterfaceEnumerator pure functions (WSTG-CONF-05)."""
import pytest

from workers.config_mgmt.tools.admin_interface_enumerator import (
    AdminInterfaceEnumerator,
    _classify_200_response,
    _extract_admin_links,
    _inject_platform_paths,
    _load_wordlist,
)


# ── _load_wordlist ────────────────────────────────────────────────────────────

def test_load_wordlist_returns_list_of_strings(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("/admin\n/manager\n/admin\n")
    result = _load_wordlist(str(wl))
    assert "/admin" in result
    assert "/manager" in result


def test_load_wordlist_deduplicates(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("/admin\n/admin\n/manager\n")
    result = _load_wordlist(str(wl))
    assert result.count("/admin") == 1


def test_load_wordlist_strips_whitespace(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("  /admin  \n  /manager  \n")
    result = _load_wordlist(str(wl))
    assert "/admin" in result
    assert "  /admin  " not in result


def test_load_wordlist_skips_empty_lines(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("/admin\n\n/manager\n\n")
    result = _load_wordlist(str(wl))
    assert "" not in result


def test_load_wordlist_skips_comment_lines(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("# This is a comment\n/admin\n")
    result = _load_wordlist(str(wl))
    assert "# This is a comment" not in result
    assert "/admin" in result


def test_load_wordlist_missing_file_returns_empty_list():
    result = _load_wordlist("/nonexistent/path/wordlist.txt")
    assert result == []


# ── _inject_platform_paths ────────────────────────────────────────────────────

def test_inject_platform_paths_wordpress():
    result = _inject_platform_paths(["wordpress 6.2"])
    assert "/wp-admin" in result
    assert "/wp-login.php" in result
    assert "/wp-admin/admin-ajax.php" in result


def test_inject_platform_paths_django():
    result = _inject_platform_paths(["django 4.2"])
    assert "/admin/" in result
    assert "/django-admin/" in result


def test_inject_platform_paths_spring_actuator():
    result = _inject_platform_paths(["spring boot 3.0"])
    assert "/actuator" in result
    assert "/actuator/env" in result
    assert "/actuator/health" in result


def test_inject_platform_paths_tomcat():
    result = _inject_platform_paths(["apache tomcat 9"])
    assert "/manager/html" in result
    assert "/host-manager/html" in result


def test_inject_platform_paths_joomla():
    result = _inject_platform_paths(["joomla 4.3"])
    assert "/administrator/" in result
    assert "/administrator/index.php" in result


def test_inject_platform_paths_laravel():
    result = _inject_platform_paths(["laravel 10"])
    assert "/horizon" in result
    assert "/telescope" in result


def test_inject_platform_paths_jenkins():
    result = _inject_platform_paths(["jenkins 2.400"])
    assert "/jenkins" in result


def test_inject_platform_paths_kibana():
    result = _inject_platform_paths(["kibana 8.0"])
    assert "/kibana" in result
    assert "/app/kibana" in result


def test_inject_platform_paths_unknown_platform_returns_empty():
    result = _inject_platform_paths(["unknown framework 1.0"])
    assert result == []


def test_inject_platform_paths_empty_list_returns_empty():
    result = _inject_platform_paths([])
    assert result == []


def test_inject_platform_paths_case_insensitive():
    result = _inject_platform_paths(["WordPress 6.2"])
    assert "/wp-admin" in result


# ── _classify_200_response ────────────────────────────────────────────────────

def test_classify_200_no_password_field_is_high():
    severity, vuln_type = _classify_200_response("<html><body>Welcome Admin</body></html>")
    assert severity == "high"
    assert vuln_type == "admin_interface_exposed_unauthenticated"


def test_classify_200_with_password_field_is_medium():
    html = '<html><form><input type="password" name="pass"/></form></html>'
    severity, vuln_type = _classify_200_response(html)
    assert severity == "medium"
    assert vuln_type == "admin_interface_exposed"


def test_classify_200_password_type_detection_case_insensitive():
    html = '<input TYPE="PASSWORD" name="pass"/>'
    severity, _ = _classify_200_response(html)
    assert severity == "medium"


def test_classify_200_empty_body_is_high():
    severity, _ = _classify_200_response("")
    assert severity == "high"


# ── _extract_admin_links ──────────────────────────────────────────────────────

def test_extract_admin_links_finds_href_with_admin_keyword():
    html = '<html><body><a href="/admin/panel">Panel</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert "/admin/panel" in result


def test_extract_admin_links_finds_form_action():
    html = '<html><body><form action="/manage/settings"></form></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert "/manage/settings" in result


def test_extract_admin_links_skips_external_urls():
    html = '<html><body><a href="https://evil.com/admin">bad</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert "https://evil.com/admin" not in result


def test_extract_admin_links_skips_non_admin_hrefs():
    html = '<html><body><a href="/login">login</a><a href="/dashboard">dash</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    for link in result:
        assert any(kw in link for kw in [
            "admin", "administrator", "manage", "manager", "control",
            "console", "panel", "backend", "backoffice", "setup",
            "config", "cpanel", "webmin", "plesk", "dashboard",
        ])


def test_extract_admin_links_deduplicates():
    html = '<html><body><a href="/admin">1</a><a href="/admin">2</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert result.count("/admin") == 1


def test_extract_admin_links_empty_html_returns_empty():
    result = _extract_admin_links("", "https://example.com")
    assert result == []


# ── AdminInterfaceEnumerator class ────────────────────────────────────────────

def test_tool_has_correct_name():
    assert AdminInterfaceEnumerator.name == "admin_interface_enumerator"


def test_build_command_raises():
    tool = AdminInterfaceEnumerator()
    with pytest.raises(NotImplementedError):
        tool.build_command(object())


def test_parse_output_raises():
    tool = AdminInterfaceEnumerator()
    with pytest.raises(NotImplementedError):
        tool.parse_output("")
