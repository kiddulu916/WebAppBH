"""Account enumeration testing tool (WSTG-IDNT-04).

Thin wrapper over the standalone ``account_enum_probe`` module. Builds a JSON
config from the target profile's ``account_enum`` block and runs the probe as a
subprocess; parsing is delegated to the base class' JSON contract.
"""

import json

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class AccountEnumerator(IdentityMgmtTool):
    """Test for account enumeration vulnerabilities (WSTG-IDNT-04)."""

    name = "account_enumerator"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = (
            target_url
            if target_url.startswith(("http://", "https://"))
            else f"https://{target_url}"
        )

        profile = getattr(target, "target_profile", None) or {}
        account_enum = profile.get("account_enum", {})

        config = {"base_url": base_url, "account_enum": account_enum}
        if credentials and credentials.get("token"):
            config["token"] = credentials["token"]

        return [
            "python3", "-m",
            "workers.identity_mgmt.tools.account_enum_probe",
            "--config", json.dumps(config),
        ]

    def parse_output(self, stdout):
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
