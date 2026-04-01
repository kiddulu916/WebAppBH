"""Tests for session management tools."""
from unittest.mock import MagicMock

from workers.session_mgmt.concurrency import WeightClass


def test_session_token_tester_weight():
    from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
    assert SessionTokenTester.weight_class == WeightClass.HEAVY


def test_session_token_tester_build_command():
    from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
    tool = SessionTokenTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_session_token_tester_parse_output():
    from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
    tool = SessionTokenTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_session_timeout_tester_weight():
    from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
    assert SessionTimeoutTester.weight_class == WeightClass.LIGHT


def test_session_timeout_tester_build_command():
    from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
    tool = SessionTimeoutTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_session_timeout_tester_parse_output():
    from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
    tool = SessionTimeoutTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_cookie_attribute_tester_weight():
    from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
    assert CookieAttributeTester.weight_class == WeightClass.LIGHT


def test_cookie_attribute_tester_build_command():
    from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
    tool = CookieAttributeTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_cookie_attribute_tester_parse_output():
    from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
    tool = CookieAttributeTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_session_fixation_tester_weight():
    from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
    assert SessionFixationTester.weight_class == WeightClass.LIGHT


def test_session_fixation_tester_build_command():
    from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
    tool = SessionFixationTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_session_fixation_tester_parse_output():
    from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
    tool = SessionFixationTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_csrf_tester_weight():
    from workers.session_mgmt.tools.csrf_tester import CsrfTester
    assert CsrfTester.weight_class == WeightClass.HEAVY


def test_csrf_tester_build_command():
    from workers.session_mgmt.tools.csrf_tester import CsrfTester
    tool = CsrfTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_csrf_tester_parse_output():
    from workers.session_mgmt.tools.csrf_tester import CsrfTester
    tool = CsrfTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_concurrent_session_tester_weight():
    from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
    assert ConcurrentSessionTester.weight_class == WeightClass.LIGHT


def test_concurrent_session_tester_build_command():
    from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
    tool = ConcurrentSessionTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_concurrent_session_tester_parse_output():
    from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
    tool = ConcurrentSessionTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_session_termination_tester_weight():
    from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
    assert SessionTerminationTester.weight_class == WeightClass.LIGHT


def test_session_termination_tester_build_command():
    from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
    tool = SessionTerminationTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_session_termination_tester_parse_output():
    from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
    tool = SessionTerminationTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_session_persistence_tester_weight():
    from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
    assert SessionPersistenceTester.weight_class == WeightClass.LIGHT


def test_session_persistence_tester_build_command():
    from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
    tool = SessionPersistenceTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_session_persistence_tester_parse_output():
    from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
    tool = SessionPersistenceTester()
    results = tool.parse_output("")
    assert isinstance(results, list)


def test_logout_functionality_tester_weight():
    from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
    assert LogoutFunctionalityTester.weight_class == WeightClass.LIGHT


def test_logout_functionality_tester_build_command():
    from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
    tool = LogoutFunctionalityTester()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)


def test_logout_functionality_tester_parse_output():
    from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
    tool = LogoutFunctionalityTester()
    results = tool.parse_output("")
    assert isinstance(results, list)
