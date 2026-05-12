# workers/info_gathering/tools/whatweb.py
"""WhatWeb wrapper — application-layer fingerprint for a single host."""
import json

from workers.info_gathering.base_tool import InfoGatheringTool


class WhatWeb(InfoGatheringTool):
    """Application-layer fingerprint using WhatWeb."""

    async def execute(self, target_id: int, **kwargs) -> dict[str, int]:
        _ = target_id  # consumed via the pipeline preamble's asset_id (Phase 3)
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return {"found": 0}

        cmd = ["whatweb", "--json", "-"]
        if intensity == "high":
            cmd += ["-a", "3"]
        cmd.append(f"https://{host}")

        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
        except Exception:
            return {"found": 0}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"found": 0}
        if not isinstance(data, list):
            return {"found": 0}

        count = 0
        for entry in data:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "_probe": "app_fingerprint",
                    "host": entry.get("target", ""),
                    "plugins": entry.get("plugins", {}),
                },
            )
            count += 1
        return {"found": count}
