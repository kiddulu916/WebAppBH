from unittest.mock import MagicMock

from workers.authentication.concurrency import WeightClass


def test_credential_transport_tester_is_light():
    from workers.authentication.tools.credential_transport_tester import CredentialTransportTester
    assert CredentialTransportTester.weight_class == WeightClass.LIGHT


def test_default_credential_tester_is_light():
    from workers.authentication.tools.default_credential_tester import DefaultCredentialTester
    assert DefaultCredentialTester.weight_class == WeightClass.LIGHT


def test_lockout_tester_is_light():
    from workers.authentication.tools.lockout_tester import LockoutTester
    assert LockoutTester.weight_class == WeightClass.LIGHT


def test_auth_bypass_tester_is_light():
    from workers.authentication.tools.auth_bypass_tester import AuthBypassTester
    assert AuthBypassTester.weight_class == WeightClass.LIGHT


def test_remember_password_tester_is_light():
    from workers.authentication.tools.remember_password_tester import RememberPasswordTester
    assert RememberPasswordTester.weight_class == WeightClass.LIGHT


def test_browser_cache_weakness_tester_is_light():
    from workers.authentication.tools.browser_cache_weakness_tester import BrowserCacheWeaknessTester
    assert BrowserCacheWeaknessTester.weight_class == WeightClass.LIGHT


def test_password_policy_tester_is_light():
    from workers.authentication.tools.password_policy_tester import PasswordPolicyTester
    assert PasswordPolicyTester.weight_class == WeightClass.LIGHT


def test_security_question_tester_is_light():
    from workers.authentication.tools.security_question_tester import SecurityQuestionTester
    assert SecurityQuestionTester.weight_class == WeightClass.LIGHT


def test_password_change_tester_is_light():
    from workers.authentication.tools.password_change_tester import PasswordChangeTester
    assert PasswordChangeTester.weight_class == WeightClass.LIGHT


def test_multi_channel_auth_tester_is_light():
    from workers.authentication.tools.multi_channel_auth_tester import MultiChannelAuthTester
    assert MultiChannelAuthTester.weight_class == WeightClass.LIGHT