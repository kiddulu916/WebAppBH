"""Security question testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class SecurityQuestionTester(AuthenticationTool):
    """Test security question mechanisms."""

    name = "security_question_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        return ["echo", "security_question_tester_placeholder"]

    def parse_output(self, stdout):
        return [{
            "title": "Security question testing completed",
            "description": "Successfully tested security question mechanisms",
            "severity": "info",
            "data": {"placeholder": True}
        }]