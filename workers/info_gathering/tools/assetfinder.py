# workers/info_gathering/tools/assetfinder.py
"""Assetfinder wrapper — passive subdomain discovery."""

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class Assetfinder(InfoGatheringTool):
    """Find subdomains using Assetfinder."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["assetfinder", "--subs-only", target.base_domain]
        try:
            stdout = await self.run_subprocess(cmd)
        except Exception as exc:
            logger.error("assetfinder failed", domain=target.base_domain, error=str(exc))
            return

        for line in stdout.strip().splitlines():
            host = line.strip()
            if host:
                await self.save_asset(target_id, "subdomain", host, "assetfinder")