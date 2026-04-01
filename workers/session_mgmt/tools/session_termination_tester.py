"""Session invalidation on logout testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionTerminationTester(SessionMgmtTool):
    """Test session invalidation on logout (WSTG 4.6.7)."""

    name = "session_termination_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        """Build command to test session termination."""
        return ["echo", "session_termination_tester_placeholder"]

    def parse_output(self, stdout):
        """Parse session termination testing results."""
        return []
