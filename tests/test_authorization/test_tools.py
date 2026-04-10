"""Tests for authorization tools."""
import json
from unittest.mock import MagicMock

from workers.authorization.concurrency import WeightClass


class TestDirectoryTraversalTester:
    def test_weight_class(self):
        from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
        assert DirectoryTraversalTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
        assert DirectoryTraversalTester().name == "directory_traversal_tester"

    def test_build_command(self):
        from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
        tool = DirectoryTraversalTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)
        assert cmd[0] == "python3"

    def test_parse_output_valid_json(self):
        from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
        tool = DirectoryTraversalTester()
        data = [{"title": "test", "severity": "high", "data": {}}]
        result = tool.parse_output(json.dumps(data))
        assert result == data

    def test_parse_output_invalid_json(self):
        from workers.authorization.tools.directory_traversal_tester import DirectoryTraversalTester
        tool = DirectoryTraversalTester()
        result = tool.parse_output("not json")
        assert result == []


class TestAuthzBypassTester:
    def test_weight_class(self):
        from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
        assert AuthzBypassTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
        assert AuthzBypassTester().name == "authz_bypass_tester"

    def test_build_command(self):
        from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
        tool = AuthzBypassTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.authorization.tools.authz_bypass_tester import AuthzBypassTester
        tool = AuthzBypassTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestPrivilegeEscalationTester:
    def test_weight_class(self):
        from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
        assert PrivilegeEscalationTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
        assert PrivilegeEscalationTester().name == "privilege_escalation_tester"

    def test_build_command(self):
        from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
        tool = PrivilegeEscalationTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.authorization.tools.privilege_escalation_tester import PrivilegeEscalationTester
        tool = PrivilegeEscalationTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestIdorTester:
    def test_weight_class(self):
        from workers.authorization.tools.idor_tester import IdorTester
        assert IdorTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authorization.tools.idor_tester import IdorTester
        assert IdorTester().name == "idor_tester"

    def test_build_command(self):
        from workers.authorization.tools.idor_tester import IdorTester
        tool = IdorTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.authorization.tools.idor_tester import IdorTester
        tool = IdorTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)
