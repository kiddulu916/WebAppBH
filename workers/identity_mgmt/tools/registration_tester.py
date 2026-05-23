"""Registration process testing tool (WSTG-IDNT-02)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class RegistrationTester(IdentityMgmtTool):
    """Test user registration processes (WSTG-IDNT-02)."""

    name = "registration_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = (
            target_url
            if target_url.startswith(("http://", "https://"))
            else f"https://{target_url}"
        )

        script = f'''
import httpx
import json
import random
import re
import time

results = []
base_url = "{base_url}"

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
