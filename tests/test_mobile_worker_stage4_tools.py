import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# FridaCryptoHooker tests
# ---------------------------------------------------------------------------


def test_frida_crypto_hooker_has_inline_script():
    from workers.mobile_worker.tools.frida_crypto_hooker import FridaCryptoHookerTool
    tool = FridaCryptoHookerTool()
    assert isinstance(tool.FRIDA_SCRIPT, str)
    assert "Cipher" in tool.FRIDA_SCRIPT or "crypto" in tool.FRIDA_SCRIPT.lower()


def test_frida_crypto_hooker_parse_findings():
    from workers.mobile_worker.tools.frida_crypto_hooker import FridaCryptoHookerTool
    tool = FridaCryptoHookerTool()
    output = """[HOOK] Cipher.init: algorithm=DES/ECB/PKCS5Padding
[HOOK] SSLContext.init: custom TrustManager detected
[HOOK] HttpURLConnection: plaintext HTTP to http://api.example.com
"""
    findings = tool._parse_output(output)
    assert len(findings) >= 2
    types = [f["type"] for f in findings]
    assert "weak_crypto" in types or "ssl_issue" in types or "plaintext_http" in types


def test_frida_crypto_hooker_is_dynamic_weight():
    from workers.mobile_worker.tools.frida_crypto_hooker import FridaCryptoHookerTool
    from workers.mobile_worker.concurrency import WeightClass
    tool = FridaCryptoHookerTool()
    assert tool.weight_class == WeightClass.DYNAMIC


def test_frida_crypto_hooker_script_timeout():
    from workers.mobile_worker.tools.frida_crypto_hooker import FridaCryptoHookerTool
    tool = FridaCryptoHookerTool()
    assert tool.SCRIPT_TIMEOUT == 60


# ---------------------------------------------------------------------------
# FridaRootDetector tests
# ---------------------------------------------------------------------------


def test_frida_root_detector_has_inline_script():
    from workers.mobile_worker.tools.frida_root_detector import FridaRootDetectorTool
    tool = FridaRootDetectorTool()
    assert isinstance(tool.FRIDA_SCRIPT, str)
    assert "root" in tool.FRIDA_SCRIPT.lower() or "RootBeer" in tool.FRIDA_SCRIPT


def test_frida_root_detector_parse_findings():
    from workers.mobile_worker.tools.frida_root_detector import FridaRootDetectorTool
    tool = FridaRootDetectorTool()
    output = """[HOOK] RootBeer.isRooted() called — bypassed (returned false)
[HOOK] Runtime.exec: su — root check detected
"""
    findings = tool._parse_output(output)
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# FridaComponentProber tests
# ---------------------------------------------------------------------------


def test_frida_component_prober_builds_am_start_command():
    from workers.mobile_worker.tools.frida_component_prober import FridaComponentProberTool
    tool = FridaComponentProberTool()
    cmd = tool._build_am_start_cmd("com.test.app", ".AdminActivity")
    assert cmd[0] == "adb"
    assert "am" in cmd
    assert "start" in cmd


def test_frida_component_prober_handles_empty_components():
    from workers.mobile_worker.tools.frida_component_prober import FridaComponentProberTool
    tool = FridaComponentProberTool()
    # Should not crash with empty list
    assert tool._build_probe_commands("com.test.app", []) == []


@pytest.mark.anyio
async def test_frida_tools_adb_health_check_method():
    from workers.mobile_worker.tools.frida_crypto_hooker import FridaCryptoHookerTool
    tool = FridaCryptoHookerTool()
    # Should have the health check method
    assert hasattr(tool, "_check_emulator_health")
