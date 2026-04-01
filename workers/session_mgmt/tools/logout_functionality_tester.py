"""Logout functionality session clearing testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class LogoutFunctionalityTester(SessionMgmtTool):
    """Test logout properly clears session (WSTG 4.6.9)."""

    name = "logout_functionality_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        """Build command to test logout functionality."""
        return ["echo", "logout_functionality_tester_placeholder"]

    def parse_output(self, stdout):
        """Parse logout functionality testing results."""
        return []
