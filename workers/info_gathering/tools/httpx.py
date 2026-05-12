# workers/info_gathering/tools/httpx.py
"""Httpx wrapper — single-host HTTP liveness probe."""
import json
import os
import tempfile

from workers.info_gathering.base_tool import InfoGatheringTool


class Httpx(InfoGatheringTool):
    """HTTP liveness probe using the httpx binary against a single host."""

    async def execute(self, target_id: int, **kwargs):
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return {"found": 0}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(host)
            input_file = f.name

        try:
            cmd = [
                "httpx", "-l", input_file,
                "-json", "-silent", "-status-code", "-title",
                "-tech-detect", "-follow-redirects",
            ]
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
            count = 0
            for line in stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                await self.save_observation(
                    asset_id=asset_id,
                    tech_stack={
                        "_probe": "liveness",
                        "url": data.get("url", ""),
                        "tech": data.get("tech", []),
                    },
                    page_title=data.get("title"),
                    status_code=data.get("status_code"),
                )
                count += 1
            return {"found": count}
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)
