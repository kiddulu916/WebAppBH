"""Session idle and absolute timeout testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionTimeoutTester(SessionMgmtTool):
    """Test session idle and absolute timeout (WSTG 4.6.2)."""

    name = "session_timeout_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        """Build command to test session timeout behavior."""
        return ["echo", "session_timeout_tester_placeholder"]

    def parse_output(self, stdout):
        """Parse session timeout testing results."""
        return []
