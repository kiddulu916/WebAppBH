"""Tests for authentication worker tools."""
import json
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from workers.authentication.concurrency import WeightClass


class TestCredentialTransportTester:
    def test_weight_class(self):
        from workers.authentication.tools.credential_transport_tester import CredentialTransportTester
        assert CredentialTransportTester.weight_class == WeightClass.LIGHT

    def test_name(self):
        from workers.authentication.tools.credential_transport_tester import CredentialTransportTester
        assert CredentialTransportTester().name == "credential_transport_tester"

    def test_build_command_returns_list(self):
        from workers.authentication.tools.credential_transport_tester import CredentialTransportTester
        tool = CredentialTransportTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)
        assert cmd[0] == "python3"

    def test_parse_output_valid_json(self):
        from workers.authentication.tools.credential_transport_tester import CredentialTransportTester
        tool = CredentialTransportTester()
        data = [{"title": "test", "severity": "info", "data": {}}]
        result = tool.parse_output(json.dumps(data))
        assert result == data

    def test_parse_output_invalid_json(self):
        from workers.authentication.tools.credential_transport_tester import CredentialTransportTester
        tool = CredentialTransportTester()
        result = tool.parse_output("not json")
        assert result == []


class TestDefaultCredentialTester:
    def test_weight_class(self):
        from workers.authentication.tools.default_credential_tester import DefaultCredentialTester
        assert DefaultCredentialTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.default_credential_tester import DefaultCredentialTester
        assert DefaultCredentialTester().name == "default_credential_tester"

    def test_build_command(self):
        from workers.authentication.tools.default_credential_tester import DefaultCredentialTester
        tool = DefaultCredentialTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)
        assert "python3" in cmd[0]

    def test_parse_output(self):
        from workers.authentication.tools.default_credential_tester import DefaultCredentialTester
        tool = DefaultCredentialTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestLockoutTester:
    def test_weight_class(self):
        from workers.authentication.tools.lockout_tester import LockoutTester
        assert LockoutTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.lockout_tester import LockoutTester
        assert LockoutTester().name == "lockout_tester"

    def test_build_command(self):
        from workers.authentication.tools.lockout_tester import LockoutTester
        tool = LockoutTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)


class TestAuthBypassTester:
    def test_weight_class(self):
        from workers.authentication.tools.auth_bypass_tester import AuthBypassTester
        assert AuthBypassTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.auth_bypass_tester import AuthBypassTester
        assert AuthBypassTester().name == "auth_bypass_tester"


class TestRememberPasswordTester:
    def test_weight_class(self):
        from workers.authentication.tools.remember_password_tester import RememberPasswordTester
        assert RememberPasswordTester.weight_class == WeightClass.LIGHT

    def test_name(self):
        from workers.authentication.tools.remember_password_tester import RememberPasswordTester
        assert RememberPasswordTester().name == "remember_password_tester"


class TestBrowserCacheWeaknessTester:
    def test_weight_class(self):
        from workers.authentication.tools.browser_cache_weakness_tester import BrowserCacheWeaknessTester
        assert BrowserCacheWeaknessTester.weight_class == WeightClass.LIGHT

    def test_name(self):
        from workers.authentication.tools.browser_cache_weakness_tester import BrowserCacheWeaknessTester
        assert BrowserCacheWeaknessTester().name == "browser_cache_weakness_tester"


class TestPasswordPolicyTester:
    def test_weight_class(self):
        from workers.authentication.tools.password_policy_tester import PasswordPolicyTester
        assert PasswordPolicyTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.password_policy_tester import PasswordPolicyTester
        assert PasswordPolicyTester().name == "password_policy_tester"


class TestSecurityQuestionTester:
    def test_weight_class(self):
        from workers.authentication.tools.security_question_tester import SecurityQuestionTester
        assert SecurityQuestionTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.security_question_tester import SecurityQuestionTester
        assert SecurityQuestionTester().name == "security_question_tester"


class TestPasswordChangeTester:
    def test_weight_class(self):
        from workers.authentication.tools.password_change_tester import PasswordChangeTester
        assert PasswordChangeTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.password_change_tester import PasswordChangeTester
        assert PasswordChangeTester().name == "password_change_tester"


class TestMultiChannelAuthTester:
    def test_weight_class(self):
        from workers.authentication.tools.multi_channel_auth_tester import MultiChannelAuthTester
        assert MultiChannelAuthTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.authentication.tools.multi_channel_auth_tester import MultiChannelAuthTester
        assert MultiChannelAuthTester().name == "multi_channel_auth_tester"
