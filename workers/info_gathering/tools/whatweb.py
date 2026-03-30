# workers/info_gathering/tools/whatweb.py
"""WhatWeb wrapper — web server fingerprinting."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool


class WhatWeb(InfoGatheringTool):
    """Web server fingerprinting using WhatWeb."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["whatweb", "--json", "-", f"https://{target.base_domain}"]
        try:
            stdout = await self.run_subprocess(cmd)
        except Exception:
            return

        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    plugins = entry.get("plugins", {})
                    await self.save_observation(
                        target_id, "web_fingerprint",
                        {"host": entry.get("target", ""), "plugins": plugins},
                        "whatweb"
                    )
        except json.JSONDecodeError:
            pass