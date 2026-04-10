"""Tests for session management tools."""
import json
from unittest.mock import MagicMock

from workers.session_mgmt.concurrency import WeightClass


class TestSessionTokenTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
        assert SessionTokenTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
        assert SessionTokenTester().name == "session_token_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
        tool = SessionTokenTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)
        assert cmd[0] == "python3"

    def test_parse_output_valid_json(self):
        from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
        tool = SessionTokenTester()
        data = [{"title": "test", "severity": "info", "data": {}}]
        result = tool.parse_output(json.dumps(data))
        assert result == data

    def test_parse_output_invalid_json(self):
        from workers.session_mgmt.tools.session_token_tester import SessionTokenTester
        tool = SessionTokenTester()
        result = tool.parse_output("not json")
        assert result == []


class TestSessionTimeoutTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
        assert SessionTimeoutTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
        assert SessionTimeoutTester().name == "session_timeout_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
        tool = SessionTimeoutTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.session_timeout_tester import SessionTimeoutTester
        tool = SessionTimeoutTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestCookieAttributeTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
        assert CookieAttributeTester.weight_class == WeightClass.LIGHT

    def test_name(self):
        from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
        assert CookieAttributeTester().name == "cookie_attribute_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
        tool = CookieAttributeTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.cookie_attribute_tester import CookieAttributeTester
        tool = CookieAttributeTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestSessionFixationTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
        assert SessionFixationTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
        assert SessionFixationTester().name == "session_fixation_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
        tool = SessionFixationTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.session_fixation_tester import SessionFixationTester
        tool = SessionFixationTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestCsrfTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.csrf_tester import CsrfTester
        assert CsrfTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.csrf_tester import CsrfTester
        assert CsrfTester().name == "csrf_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.csrf_tester import CsrfTester
        tool = CsrfTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.csrf_tester import CsrfTester
        tool = CsrfTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestConcurrentSessionTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
        assert ConcurrentSessionTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
        assert ConcurrentSessionTester().name == "concurrent_session_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
        tool = ConcurrentSessionTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.concurrent_session_tester import ConcurrentSessionTester
        tool = ConcurrentSessionTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestSessionTerminationTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
        assert SessionTerminationTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
        assert SessionTerminationTester().name == "session_termination_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
        tool = SessionTerminationTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.session_termination_tester import SessionTerminationTester
        tool = SessionTerminationTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestSessionPersistenceTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
        assert SessionPersistenceTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
        assert SessionPersistenceTester().name == "session_persistence_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
        tool = SessionPersistenceTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.session_persistence_tester import SessionPersistenceTester
        tool = SessionPersistenceTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)


class TestLogoutFunctionalityTester:
    def test_weight_class(self):
        from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
        assert LogoutFunctionalityTester.weight_class == WeightClass.HEAVY

    def test_name(self):
        from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
        assert LogoutFunctionalityTester().name == "logout_functionality_tester"

    def test_build_command(self):
        from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
        tool = LogoutFunctionalityTester()
        target = MagicMock(target_value="example.com")
        cmd = tool.build_command(target)
        assert isinstance(cmd, list)

    def test_parse_output(self):
        from workers.session_mgmt.tools.logout_functionality_tester import LogoutFunctionalityTester
        tool = LogoutFunctionalityTester()
        result = tool.parse_output("[]")
        assert isinstance(result, list)
