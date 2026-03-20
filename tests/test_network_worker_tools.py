"""Tests for network_worker tools."""

import os

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_network_worker_concurrency_weight_classes():
    from workers.network_worker.concurrency import WeightClass

    assert WeightClass.LIGHT.value == "light"
    assert WeightClass.MEDIUM.value == "medium"
    assert WeightClass.HEAVY.value == "heavy"


def test_network_worker_concurrency_get_semaphore():
    from workers.network_worker.concurrency import WeightClass, get_semaphore

    for wc in WeightClass:
        sem = get_semaphore(wc)
        assert sem is not None


def test_network_test_tool_is_abstract():
    import inspect
    from workers.network_worker.base_tool import NetworkTestTool

    assert inspect.isabstract(NetworkTestTool)


def test_network_test_tool_has_required_helpers():
    from workers.network_worker.base_tool import NetworkTestTool

    assert hasattr(NetworkTestTool, "run_subprocess")
    assert hasattr(NetworkTestTool, "check_cooldown")
    assert hasattr(NetworkTestTool, "update_tool_state")
    assert hasattr(NetworkTestTool, "_save_location")
    assert hasattr(NetworkTestTool, "_save_observation_tech_stack")
    assert hasattr(NetworkTestTool, "_save_vulnerability")
    assert hasattr(NetworkTestTool, "_load_oos_attacks")
    assert hasattr(NetworkTestTool, "_get_non_http_locations")


def test_load_oos_attacks_missing_file(tmp_path):
    from workers.network_worker.base_tool import NetworkTestTool

    class DummyTool(NetworkTestTool):
        name = "dummy"
        weight_class = None
        async def execute(self, *a, **kw):
            return {}

    tool = DummyTool()
    result = tool._load_oos_attacks_sync(str(tmp_path / "nonexistent"))
    assert result == []


def test_load_oos_attacks_reads_profile(tmp_path):
    import json
    from workers.network_worker.base_tool import NetworkTestTool

    class DummyTool(NetworkTestTool):
        name = "dummy"
        weight_class = None
        async def execute(self, *a, **kw):
            return {}

    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"oos_attacks": ["dos", "exploit/multi/handler"]}))

    tool = DummyTool()
    result = tool._load_oos_attacks_sync(str(profile))
    assert result == ["dos", "exploit/multi/handler"]


def test_default_creds_yaml_loads():
    import yaml
    from pathlib import Path

    creds_path = Path(__file__).resolve().parent.parent / "workers" / "network_worker" / "wordlists" / "default_creds.yaml"
    with open(creds_path) as f:
        creds = yaml.safe_load(f)

    assert isinstance(creds, dict)
    assert "ssh" in creds
    assert "mysql" in creds
    assert "ftp" in creds
    for service, pairs in creds.items():
        assert isinstance(pairs, list)
        for pair in pairs:
            assert len(pair) == 2


def test_cve_to_msf_yaml_loads():
    import yaml
    from pathlib import Path

    map_path = Path(__file__).resolve().parent.parent / "workers" / "network_worker" / "mappings" / "cve_to_msf.yaml"
    with open(map_path) as f:
        mappings = yaml.safe_load(f)

    assert isinstance(mappings, dict)
    assert "CVE-2017-0144" in mappings
    for cve_id, info in mappings.items():
        assert "module" in info
        assert "service" in info
        assert "ports" in info
        assert isinstance(info["ports"], list)


# ===================================================================
# NaabuTool tests
# ===================================================================

def test_naabu_tool_attributes():
    from workers.network_worker.tools.naabu_tool import NaabuTool
    from workers.network_worker.concurrency import WeightClass

    tool = NaabuTool()
    assert tool.name == "naabu"
    assert tool.weight_class == WeightClass.LIGHT


def test_naabu_tool_build_command():
    from workers.network_worker.tools.naabu_tool import NaabuTool

    tool = NaabuTool()
    cmd = tool.build_command("192.168.1.1")
    assert "naabu" in cmd
    assert "-host" in cmd
    assert "192.168.1.1" in cmd
    assert "-json" in cmd


def test_naabu_tool_parse_output():
    import json
    from workers.network_worker.tools.naabu_tool import NaabuTool

    tool = NaabuTool()
    lines = [
        json.dumps({"host": "192.168.1.1", "port": 22}),
        json.dumps({"host": "192.168.1.1", "port": 3306}),
        "",
        "some random log line",
    ]
    raw = "\n".join(lines)
    results = tool.parse_output(raw)
    assert len(results) == 2
    assert {"host": "192.168.1.1", "port": 22} in results
    assert {"host": "192.168.1.1", "port": 3306} in results


def test_naabu_tool_parse_output_empty():
    from workers.network_worker.tools.naabu_tool import NaabuTool

    tool = NaabuTool()
    assert tool.parse_output("") == []
    assert tool.parse_output("   ") == []


# ===================================================================
# NmapTool tests
# ===================================================================

def test_nmap_tool_attributes():
    from workers.network_worker.tools.nmap_tool import NmapTool
    from workers.network_worker.concurrency import WeightClass

    tool = NmapTool()
    assert tool.name == "nmap"
    assert tool.weight_class == WeightClass.MEDIUM


def test_nmap_tool_build_command():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    cmd = tool.build_command("192.168.1.1", [22, 80, 445])
    assert "nmap" in cmd
    assert "-sV" in cmd
    assert "-sC" in cmd
    assert "--script=vuln" in cmd
    assert "-oX" in cmd
    assert "-p" in cmd
    assert "22,80,445" in cmd


def test_nmap_tool_build_command_excludes_oos_scripts():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    cmd = tool.build_command("10.0.0.1", [445], oos_attacks=["smb-vuln-ms17-010", "dos"])
    cmd_str = " ".join(cmd)
    assert "exclude" in cmd_str.lower()


def test_nmap_tool_parse_xml_basic():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.2p2"/>
          </port>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds" product="Samba"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 3.10 - 4.11" accuracy="98"/>
        </os>
      </host>
    </nmaprun>"""
    results = tool.parse_xml(xml)
    assert len(results) == 1
    host = results[0]
    assert host["addr"] == "192.168.1.1"
    assert len(host["ports"]) == 2
    assert host["ports"][0]["port"] == 22
    assert host["ports"][0]["service"] == "ssh"
    assert host["ports"][0]["product"] == "OpenSSH"
    assert host["ports"][0]["version"] == "7.2p2"
    assert host["os_match"] == "Linux 3.10 - 4.11"


def test_nmap_tool_extract_cves():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    script_output = """
    smb-vuln-ms17-010:
      VULNERABLE:
      Remote Code Execution vulnerability in Microsoft SMBv1
        State: VULNERABLE
        IDs:  CVE:CVE-2017-0144
        Risk factor: HIGH
    heartbleed:
      VULNERABLE:
        IDs:  CVE:CVE-2014-0160
    """
    cves = tool.extract_cves(script_output)
    assert "CVE-2017-0144" in cves
    assert "CVE-2014-0160" in cves


# ===================================================================
# BannerGrabTool tests
# ===================================================================

def test_banner_grab_tool_attributes():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool
    from workers.network_worker.concurrency import WeightClass

    tool = BannerGrabTool()
    assert tool.name == "banner_grab"
    assert tool.weight_class == WeightClass.LIGHT


def test_banner_grab_tool_detect_ldap():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool

    tool = BannerGrabTool()
    assert tool.detect_service("0\x84") == "ldap"
    assert tool.detect_service("objectClass: top") == "ldap"
    assert tool.detect_service("LDAP") == "ldap"


def test_banner_grab_tool_detect_other_services():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool

    tool = BannerGrabTool()
    assert tool.detect_service("SSH-2.0-OpenSSH_7.2p2") == "ssh"
    assert tool.detect_service("220 ProFTPD 1.3.5") == "ftp"
    assert tool.detect_service("+OK POP3 server ready") == "pop3"
    assert tool.detect_service("* OK IMAP server ready") == "imap"
    assert tool.detect_service("220 mail.example.com ESMTP") == "smtp"


def test_banner_grab_tool_detect_unknown():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool

    tool = BannerGrabTool()
    assert tool.detect_service("") is None
    assert tool.detect_service("some random binary data") is None


# ===================================================================
# MedusaTool tests
# ===================================================================

def test_medusa_tool_attributes():
    from workers.network_worker.tools.medusa_tool import MedusaTool
    from workers.network_worker.concurrency import WeightClass

    tool = MedusaTool()
    assert tool.name == "medusa"
    assert tool.weight_class == WeightClass.MEDIUM


def test_medusa_tool_build_command():
    from workers.network_worker.tools.medusa_tool import MedusaTool

    tool = MedusaTool()
    cmd = tool.build_command("10.0.0.1", 22, "ssh", "admin", "admin")
    assert "medusa" in cmd
    assert "-h" in cmd
    assert "10.0.0.1" in cmd
    assert "-n" in cmd
    assert "22" in cmd
    # Rate limiting flags
    assert "-t" in cmd
    assert "-w" in cmd


def test_medusa_tool_parse_output_success():
    from workers.network_worker.tools.medusa_tool import MedusaTool

    tool = MedusaTool()
    raw = """
    ACCOUNT CHECK: [ssh] Host: 10.0.0.1 (1 of 1) User: admin Password: admin
    ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: admin Password: admin [SUCCESS]
    """
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["user"] == "admin"
    assert results[0]["password"] == "admin"


def test_medusa_tool_parse_output_no_success():
    from workers.network_worker.tools.medusa_tool import MedusaTool

    tool = MedusaTool()
    raw = """
    ACCOUNT CHECK: [ssh] Host: 10.0.0.1 User: admin Password: admin
    """
    results = tool.parse_output(raw)
    assert results == []


def test_medusa_tool_service_mapping():
    from workers.network_worker.tools.medusa_tool import SERVICE_TO_MEDUSA_MODULE

    assert "ssh" in SERVICE_TO_MEDUSA_MODULE
    assert "ftp" in SERVICE_TO_MEDUSA_MODULE
    assert "mysql" in SERVICE_TO_MEDUSA_MODULE
