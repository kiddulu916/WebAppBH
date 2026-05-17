# workers/info_gathering/tools/naabu.py
"""Naabu wrapper — fast port scanning."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class Naabu(InfoGatheringTool):
    """Fast port scanning using Naabu."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or not asset_id:
            return

        cmd = ["naabu", "-host", target.base_domain, "-json", "-silent"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=600)
        except Exception as exc:
            logger.error(
                "naabu failed",
                target=target.base_domain,
                error=str(exc),
            )
            return

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                port = data.get("port")
                if port:
                    await self.save_location(
                        asset_id=asset_id,
                        port=int(port),
                        protocol="tcp",
                        state="open",
                    )
            except (json.JSONDecodeError, ValueError):
                continue