"""Concurrent session limit testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class ConcurrentSessionTester(SessionMgmtTool):
    """Test concurrent session limits (WSTG 4.6.6)."""

    name = "concurrent_session_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        """Build command to test concurrent session limits."""
        return ["echo", "concurrent_session_tester_placeholder"]

    def parse_output(self, stdout):
        """Parse concurrent session testing results."""
        return []
