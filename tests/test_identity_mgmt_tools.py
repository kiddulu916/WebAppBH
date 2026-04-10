"""Tests for identity management worker tools."""
import json
from unittest.mock import MagicMock

import pytest

from workers.identity_mgmt.concurrency import WeightClass


class TestRoleEnumerator:
    def test_weight_class(self):
        from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
        assert RoleEnumerator.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
        assert RoleEnumerator().name == "role_enumerator"

    def test_build_command(self):
        from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
        tool = RoleEnumerator()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)
        assert "python3" in cmd[0]

    def test_parse_output_valid_json(self):
        from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
        tool = RoleEnumerator()
        data = [{"title": "test", "severity": "medium", "data": {}}]
        result = tool.parse_output(json.dumps(data))
        assert result == data

    def test_parse_output_invalid_json(self):
        from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
        tool = RoleEnumerator()
        result = tool.parse_output("not json")
        assert result == []


class TestRegistrationTester:
    def test_weight_class(self):
        from workers.identity_mgmt.tools.registration_tester import RegistrationTester
        assert RegistrationTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.identity_mgmt.tools.registration_tester import RegistrationTester
        assert RegistrationTester().name == "registration_tester"


class TestAccountProvisionTester:
    def test_weight_class(self):
        from workers.identity_mgmt.tools.account_provision_tester import AccountProvisionTester
        assert AccountProvisionTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.identity_mgmt.tools.account_provision_tester import AccountProvisionTester
        assert AccountProvisionTester().name == "account_provision_tester"


class TestAccountEnumerator:
    def test_weight_class(self):
        from workers.identity_mgmt.tools.account_enumerator import AccountEnumerator
        assert AccountEnumerator.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.identity_mgmt.tools.account_enumerator import AccountEnumerator
        assert AccountEnumerator().name == "account_enumerator"


class TestUsernamePolicyTester:
    def test_weight_class(self):
        from workers.identity_mgmt.tools.username_policy_tester import UsernamePolicyTester
        assert UsernamePolicyTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.identity_mgmt.tools.username_policy_tester import UsernamePolicyTester
        assert UsernamePolicyTester().name == "username_policy_tester"
