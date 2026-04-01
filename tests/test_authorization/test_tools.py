"""Tests for authorization tools."""
from unittest.mock import MagicMock

from workers.authorization.concurrency import WeightClass


def test_directory_traversal_tester_is_light():
    from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
    assert DirectoryTraversalTester.weight_class == WeightClass.LIGHT


def test_directory_traversal_tester_build_command():
    from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
    tool = DirectoryTraversalTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_directory_traversal_tester_parse_output():
    from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
    tool = DirectoryTraversalTester()
    output = "placeholder output"
    results = tool.parse_output(output)
    assert isinstance(results, list)
    assert len(results) == 1
    assert "title" in results[0]


def test_authz_bypass_tester_is_light():
    from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
    assert AuthzBypassTester.weight_class == WeightClass.LIGHT


def test_authz_bypass_tester_build_command():
    from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
    tool = AuthzBypassTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_authz_bypass_tester_parse_output():
    from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
    tool = AuthzBypassTester()
    output = "placeholder output"
    results = tool.parse_output(output)
    assert isinstance(results, list)
    assert len(results) == 1
    assert "title" in results[0]


def test_privilege_escalation_tester_is_light():
    from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
    assert PrivilegeEscalationTester.weight_class == WeightClass.LIGHT


def test_privilege_escalation_tester_build_command():
    from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
    tool = PrivilegeEscalationTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_privilege_escalation_tester_parse_output():
    from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
    tool = PrivilegeEscalationTester()
    output = "placeholder output"
    results = tool.parse_output(output)
    assert isinstance(results, list)
    assert len(results) == 1
    assert "title" in results[0]


def test_idor_tester_is_light():
    from workers.authorization.tools.idor_tester import IdorTester
    assert IdorTester.weight_class == WeightClass.LIGHT


def test_idor_tester_build_command():
    from workers.authorization.tools.idor_tester import IdorTester
    tool = IdorTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_idor_tester_parse_output():
    from workers.authorization.tools.idor_tester import IdorTester
    tool = IdorTester()
    output = "placeholder output"
    results = tool.parse_output(output)
    assert isinstance(results, list)
    assert len(results) == 1
    assert "title" in results[0]
