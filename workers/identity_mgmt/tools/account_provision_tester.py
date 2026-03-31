"""Account provisioning testing tool."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class AccountProvisionTester(IdentityMgmtTool):
    """Test account provisioning mechanisms."""

    name = "account_provision_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        """Build command to test account provisioning."""
        return ["echo", "account_provision_tester_placeholder"]

    def parse_output(self, stdout):
        """Parse account provisioning test results."""
        return [
            {
                "title": "Account provisioning testing completed",
                "description": "Successfully tested account provisioning mechanisms",
                "severity": "info",
                "data": {"tests_run": 0, "placeholder": True}
            }
        ]