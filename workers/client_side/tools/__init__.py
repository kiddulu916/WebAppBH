"""Client-side testing tool modules."""

from workers.client_side.tools.dom_xss_tester import DomXssTester
from workers.client_side.tools.clickjacking_tester import ClickjackingTester
from workers.client_side.tools.client_side_csrf_tester import ClientSideCsrfTester
from workers.client_side.tools.csp_bypass_tester import CspBypassTester
from workers.client_side.tools.html5_injection_tester import Html5InjectionTester
from workers.client_side.tools.web_storage_tester import WebStorageTester
from workers.client_side.tools.client_logic_analyzer import ClientLogicAnalyzer
from workers.client_side.tools.dom_injection_tester import DomInjectionTester
from workers.client_side.tools.resource_manipulation_tester import ResourceManipulationTester
from workers.client_side.tools.client_auth_tester import ClientAuthTester
from workers.client_side.tools.client_xss_tester import ClientXssTester
from workers.client_side.tools.css_injection_tester import CssInjectionTester
from workers.client_side.tools.malicious_upload_client_tester import MaliciousUploadClientTester

__all__ = [
    "DomXssTester",
    "ClickjackingTester",
    "ClientSideCsrfTester",
    "CspBypassTester",
    "Html5InjectionTester",
    "WebStorageTester",
    "ClientLogicAnalyzer",
    "DomInjectionTester",
    "ResourceManipulationTester",
    "ClientAuthTester",
    "ClientXssTester",
    "CssInjectionTester",
    "MaliciousUploadClientTester",
]
