from unittest.mock import MagicMock

from workers.config_mgmt.concurrency import WeightClass


def test_network_config_tester_is_light():
    from workers.config_mgmt.tools.network_config_tester import NetworkConfigTester
    assert NetworkConfigTester().weight_class == WeightClass.LIGHT


def test_network_config_tester_build_command():
    from workers.config_mgmt.tools.network_config_tester import NetworkConfigTester
    tool = NetworkConfigTester()
    target = MagicMock(url="https://example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)
    assert len(cmd) > 0


def test_platform_fingerprinter_is_light():
    from workers.config_mgmt.tools.platform_fingerprinter import PlatformFingerprinter
    assert PlatformFingerprinter().weight_class == WeightClass.LIGHT


def test_file_extension_tester_is_light():
    from workers.config_mgmt.tools.file_extension_tester import FileExtensionTester
    assert FileExtensionTester().weight_class == WeightClass.LIGHT


def test_backup_file_finder_is_light():
    from workers.config_mgmt.tools.backup_file_finder import BackupFileFinder
    assert BackupFileFinder().weight_class == WeightClass.LIGHT


def test_api_discovery_tool_is_light():
    from workers.config_mgmt.tools.api_discovery_tool import ApiDiscoveryTool
    assert ApiDiscoveryTool().weight_class == WeightClass.LIGHT


def test_http_method_tester_is_light():
    from workers.config_mgmt.tools.http_method_tester import HttpMethodTester
    assert HttpMethodTester().weight_class == WeightClass.LIGHT


def test_hsts_tester_is_light():
    from workers.config_mgmt.tools.hsts_tester import HstsTester
    assert HstsTester().weight_class == WeightClass.LIGHT


def test_rpc_tester_is_light():
    from workers.config_mgmt.tools.rpc_tester import RpcTester
    assert RpcTester().weight_class == WeightClass.LIGHT


def test_file_inclusion_tester_is_light():
    from workers.config_mgmt.tools.file_inclusion_tester import FileInclusionTester
    assert FileInclusionTester().weight_class == WeightClass.LIGHT


def test_subdomain_takeover_checker_is_light():
    from workers.config_mgmt.tools.subdomain_takeover_checker import SubdomainTakeoverChecker
    assert SubdomainTakeoverChecker().weight_class == WeightClass.LIGHT


def test_cloud_storage_auditor_is_light():
    from workers.config_mgmt.tools.cloud_storage_auditor import CloudStorageAuditor
    assert CloudStorageAuditor().weight_class == WeightClass.LIGHT