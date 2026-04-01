"""Tests for config management tools."""
from unittest.mock import MagicMock

from workers.config_mgmt.concurrency import WeightClass, get_tool_weight


def test_network_config_tester_build_command():
    from workers.config_mgmt.tools import NetworkConfigTester
    tool = NetworkConfigTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_network_config_tester_parse_output():
    from workers.config_mgmt.tools import NetworkConfigTester
    tool = NetworkConfigTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_network_config_tester_weight():
    from workers.config_mgmt.concurrency import get_tool_weight, WeightClass
    assert get_tool_weight("NetworkConfigAuditor") == WeightClass.LIGHT


def test_platform_fingerprinter_build_command():
    from workers.config_mgmt.tools import PlatformFingerprinter
    tool = PlatformFingerprinter()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_platform_fingerprinter_parse_output():
    from workers.config_mgmt.tools import PlatformFingerprinter
    tool = PlatformFingerprinter()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_file_extension_tester_build_command():
    from workers.config_mgmt.tools import FileExtensionTester
    tool = FileExtensionTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_file_extension_tester_parse_output():
    from workers.config_mgmt.tools import FileExtensionTester
    tool = FileExtensionTester()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_backup_file_finder_build_command():
    from workers.config_mgmt.tools import BackupFileFinder
    tool = BackupFileFinder()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_backup_file_finder_parse_output():
    from workers.config_mgmt.tools import BackupFileFinder
    tool = BackupFileFinder()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_api_discovery_tool_build_command():
    from workers.config_mgmt.tools import ApiDiscoveryTool
    tool = ApiDiscoveryTool()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_api_discovery_tool_parse_output():
    from workers.config_mgmt.tools import ApiDiscoveryTool
    tool = ApiDiscoveryTool()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_http_method_tester_build_command():
    from workers.config_mgmt.tools import HttpMethodTester
    tool = HttpMethodTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_http_method_tester_parse_output():
    from workers.config_mgmt.tools import HttpMethodTester
    tool = HttpMethodTester()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_hsts_tester_build_command():
    from workers.config_mgmt.tools import HstsTester
    tool = HstsTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_hsts_tester_parse_output():
    from workers.config_mgmt.tools import HstsTester
    tool = HstsTester()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_rpc_tester_build_command():
    from workers.config_mgmt.tools import RpcTester
    tool = RpcTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_rpc_tester_parse_output():
    from workers.config_mgmt.tools import RpcTester
    tool = RpcTester()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_file_inclusion_tester_build_command():
    from workers.config_mgmt.tools import FileInclusionTester
    tool = FileInclusionTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_file_inclusion_tester_parse_output():
    from workers.config_mgmt.tools import FileInclusionTester
    tool = FileInclusionTester()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_subdomain_takeover_checker_build_command():
    from workers.config_mgmt.tools import SubdomainTakeoverChecker
    tool = SubdomainTakeoverChecker()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_subdomain_takeover_checker_parse_output():
    from workers.config_mgmt.tools import SubdomainTakeoverChecker
    tool = SubdomainTakeoverChecker()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)


def test_cloud_storage_auditor_build_command():
    from workers.config_mgmt.tools import CloudStorageAuditor
    tool = CloudStorageAuditor()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_cloud_storage_auditor_parse_output():
    from workers.config_mgmt.tools import CloudStorageAuditor
    tool = CloudStorageAuditor()
    assert hasattr(tool, "parse_output")
    assert callable(tool.parse_output)
