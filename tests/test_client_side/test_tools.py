"""Tests for client-side tools."""
import sys
from unittest.mock import MagicMock, patch

import pytest

from workers.client_side.concurrency import WeightClass


@pytest.fixture(autouse=True)
def mock_playwright():
    mock_pw_module = MagicMock()
    with patch.dict(sys.modules, {"playwright.async_api": mock_pw_module}):
        yield


def test_dom_xss_tester_weight():
    from workers.client_side.tools.dom_xss_tester import DomXssTester
    assert DomXssTester.weight_class == WeightClass.HEAVY


def test_dom_xss_tester_build_command():
    from workers.client_side.tools.dom_xss_tester import DomXssTester
    tool = DomXssTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_dom_xss_tester_parse_output():
    from workers.client_side.tools.dom_xss_tester import DomXssTester
    tool = DomXssTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_clickjacking_tester_weight():
    from workers.client_side.tools.clickjacking_tester import ClickjackingTester
    assert ClickjackingTester.weight_class == WeightClass.LIGHT


def test_clickjacking_tester_build_command():
    from workers.client_side.tools.clickjacking_tester import ClickjackingTester
    tool = ClickjackingTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_clickjacking_tester_parse_output():
    from workers.client_side.tools.clickjacking_tester import ClickjackingTester
    tool = ClickjackingTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_client_side_csrf_tester_weight():
    from workers.client_side.tools.client_side_csrf_tester import ClientSideCsrfTester
    assert ClientSideCsrfTester.weight_class == WeightClass.LIGHT


def test_client_side_csrf_tester_build_command():
    from workers.client_side.tools.client_side_csrf_tester import ClientSideCsrfTester
    tool = ClientSideCsrfTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_client_side_csrf_tester_parse_output():
    from workers.client_side.tools.client_side_csrf_tester import ClientSideCsrfTester
    tool = ClientSideCsrfTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_csp_bypass_tester_weight():
    from workers.client_side.tools.csp_bypass_tester import CspBypassTester
    assert CspBypassTester.weight_class == WeightClass.LIGHT


def test_csp_bypass_tester_build_command():
    from workers.client_side.tools.csp_bypass_tester import CspBypassTester
    tool = CspBypassTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_csp_bypass_tester_parse_output():
    from workers.client_side.tools.csp_bypass_tester import CspBypassTester
    tool = CspBypassTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_html5_injection_tester_weight():
    from workers.client_side.tools.html5_injection_tester import Html5InjectionTester
    assert Html5InjectionTester.weight_class == WeightClass.LIGHT


def test_html5_injection_tester_build_command():
    from workers.client_side.tools.html5_injection_tester import Html5InjectionTester
    tool = Html5InjectionTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_html5_injection_tester_parse_output():
    from workers.client_side.tools.html5_injection_tester import Html5InjectionTester
    tool = Html5InjectionTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_web_storage_tester_weight():
    from workers.client_side.tools.web_storage_tester import WebStorageTester
    assert WebStorageTester.weight_class == WeightClass.LIGHT


def test_web_storage_tester_build_command():
    from workers.client_side.tools.web_storage_tester import WebStorageTester
    tool = WebStorageTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_web_storage_tester_parse_output():
    from workers.client_side.tools.web_storage_tester import WebStorageTester
    tool = WebStorageTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_client_logic_analyzer_weight():
    from workers.client_side.tools.client_logic_analyzer import ClientLogicAnalyzer
    assert ClientLogicAnalyzer.weight_class == WeightClass.LIGHT


def test_client_logic_analyzer_build_command():
    from workers.client_side.tools.client_logic_analyzer import ClientLogicAnalyzer
    tool = ClientLogicAnalyzer()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_client_logic_analyzer_parse_output():
    from workers.client_side.tools.client_logic_analyzer import ClientLogicAnalyzer
    tool = ClientLogicAnalyzer()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_dom_injection_tester_weight():
    from workers.client_side.tools.dom_injection_tester import DomInjectionTester
    assert DomInjectionTester.weight_class == WeightClass.LIGHT


def test_dom_injection_tester_build_command():
    from workers.client_side.tools.dom_injection_tester import DomInjectionTester
    tool = DomInjectionTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_dom_injection_tester_parse_output():
    from workers.client_side.tools.dom_injection_tester import DomInjectionTester
    tool = DomInjectionTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_resource_manipulation_tester_weight():
    from workers.client_side.tools.resource_manipulation_tester import ResourceManipulationTester
    assert ResourceManipulationTester.weight_class == WeightClass.HEAVY


def test_resource_manipulation_tester_build_command():
    from workers.client_side.tools.resource_manipulation_tester import ResourceManipulationTester
    tool = ResourceManipulationTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_resource_manipulation_tester_parse_output():
    from workers.client_side.tools.resource_manipulation_tester import ResourceManipulationTester
    tool = ResourceManipulationTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_client_auth_tester_weight():
    from workers.client_side.tools.client_auth_tester import ClientAuthTester
    assert ClientAuthTester.weight_class == WeightClass.LIGHT


def test_client_auth_tester_build_command():
    from workers.client_side.tools.client_auth_tester import ClientAuthTester
    tool = ClientAuthTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_client_auth_tester_parse_output():
    from workers.client_side.tools.client_auth_tester import ClientAuthTester
    tool = ClientAuthTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_client_xss_tester_weight():
    from workers.client_side.tools.client_xss_tester import ClientXssTester
    assert ClientXssTester.weight_class == WeightClass.HEAVY


def test_client_xss_tester_build_command():
    from workers.client_side.tools.client_xss_tester import ClientXssTester
    tool = ClientXssTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_client_xss_tester_parse_output():
    from workers.client_side.tools.client_xss_tester import ClientXssTester
    tool = ClientXssTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_css_injection_tester_weight():
    from workers.client_side.tools.css_injection_tester import CssInjectionTester
    assert CssInjectionTester.weight_class == WeightClass.LIGHT


def test_css_injection_tester_build_command():
    from workers.client_side.tools.css_injection_tester import CssInjectionTester
    tool = CssInjectionTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_css_injection_tester_parse_output():
    from workers.client_side.tools.css_injection_tester import CssInjectionTester
    tool = CssInjectionTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_malicious_upload_client_tester_weight():
    from workers.client_side.tools.malicious_upload_client_tester import MaliciousUploadClientTester
    assert MaliciousUploadClientTester.weight_class == WeightClass.LIGHT


def test_malicious_upload_client_tester_build_command():
    from workers.client_side.tools.malicious_upload_client_tester import MaliciousUploadClientTester
    tool = MaliciousUploadClientTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_malicious_upload_client_tester_parse_output():
    from workers.client_side.tools.malicious_upload_client_tester import MaliciousUploadClientTester
    tool = MaliciousUploadClientTester()
    results = tool.parse_output("")
    assert isinstance(results, list)
