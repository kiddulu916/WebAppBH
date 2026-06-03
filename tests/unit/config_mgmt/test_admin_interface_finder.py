"""Unit tests for AdminInterfaceFinder (WSTG-CONF-01 pillar 2)."""
import json
import pytest

from workers.config_mgmt.tools.admin_interface_finder import AdminInterfaceFinder


NMAP_GREPPABLE_SAMPLE = (
    "Host: 10.0.0.1 (example.com)\tPorts: "
    "21/open/tcp//ftp//ProFTPD 1.3.5e/, "
    "80/open/tcp//http//Apache httpd 2.4.41/, "
    "445/open/tcp//microsoft-ds//Samba smbd 4.11.6/, "
    "8080/open/tcp//http//Apache Tomcat 9.0.37/\t"
    "Ignored State: closed (65531)\n"
)

NMAP_EMPTY_SAMPLE = (
    "Host: 10.0.0.1 ()\tPorts: \tIgnored State: closed (65535)\n"
)

NMAP_NO_HOST_LINE = "# Nmap scan report\n# Done.\n"


def test_parse_nmap_extracts_open_service_observations():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_GREPPABLE_SAMPLE)
    types = [r["observation"]["type"] for r in results]
    assert all(t == "open_service" for t in types)
    ports = [r["observation"]["details"]["port"] for r in results]
    assert 21 in ports
    assert 80 in ports
    assert 445 in ports
    assert 8080 in ports


def test_parse_nmap_flags_known_admin_ports():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_GREPPABLE_SAMPLE)
    by_port = {r["observation"]["details"]["port"]: r["observation"]["details"] for r in results}
    assert by_port[21]["is_admin_service"] is True    # FTP
    assert by_port[445]["is_admin_service"] is True   # SMB
    assert by_port[8080]["is_admin_service"] is True  # Alt HTTP
    assert by_port[80]["is_admin_service"] is False   # plain HTTP is not admin


def test_parse_nmap_empty_ports_returns_empty_list():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_EMPTY_SAMPLE)
    assert results == []


def test_parse_nmap_no_host_line_returns_empty_list():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_NO_HOST_LINE)
    assert results == []


def test_parse_nmap_captures_service_and_banner():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_GREPPABLE_SAMPLE)
    ftp_entry = next(r for r in results if r["observation"]["details"]["port"] == 21)
    assert ftp_entry["observation"]["details"]["service"] == "ftp"
    assert "ProFTPD" in ftp_entry["observation"]["details"]["banner"]


def test_parse_output_200_yields_admin_interface():
    tool = AdminInterfaceFinder()
    raw = json.dumps([{
        "observation": {
            "type": "admin_interface",
            "value": "https://example.com/admin",
            "details": {"path": "/admin", "status": 200, "content_length": 1234, "server": "Apache"},
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "admin_interface"
    assert results[0]["observation"]["value"] == "https://example.com/admin"


def test_parse_output_redirect_yields_admin_redirect():
    tool = AdminInterfaceFinder()
    raw = json.dumps([{
        "observation": {
            "type": "admin_redirect",
            "value": "https://example.com/wp-admin",
            "details": {"path": "/wp-admin", "status": 302, "redirect_to": "/wp-login.php"},
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "admin_redirect"


def test_parse_output_invalid_json_returns_empty_list():
    tool = AdminInterfaceFinder()
    assert tool.parse_output("garbage") == []


def test_build_command_returns_nmap_with_specific_ports():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert cmd[0] == "nmap"
    assert any(a.startswith("-p") for a in cmd)
    assert "-p-" not in cmd
    assert "--host-timeout" in cmd
    assert "-sV" in cmd
    assert "--open" in cmd
    assert "-oG" in cmd
    assert "example.com" in cmd


def test_build_command_with_url_extracts_hostname():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "https://example.com/path"})()
    cmd = tool.build_command(target)
    assert "example.com" in cmd
    assert "https://" not in " ".join(cmd)


def test_build_http_probe_command_contains_admin_paths():
    tool = AdminInterfaceFinder()
    cmd = tool._build_http_probe_command("https://example.com")
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    script = cmd[2]
    assert "/wp-admin" in script
    assert "/manager/html" in script
    assert "/actuator" in script
    assert "/.git/HEAD" in script


def test_extract_host_from_url():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "https://sub.example.com:8443/path"})()
    assert tool._extract_host(target) == "sub.example.com"


def test_extract_host_from_plain_domain():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "example.com"})()
    assert tool._extract_host(target) == "example.com"
