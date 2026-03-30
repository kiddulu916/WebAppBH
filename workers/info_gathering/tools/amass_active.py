# workers/info_gathering/tools/amass_active.py
"""AmassActive wrapper — active subdomain enumeration with zone transfer and brute force."""

from workers.info_gathering.base_tool import InfoGatheringTool


class AmassActive(InfoGatheringTool):
    """Active subdomain enumeration using Amass with zone transfer attempts."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        # Active enumeration with brute force
        cmd = ["amass", "enum", "-active", "-d", target.base_domain, "-brute"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=1200)
        except Exception:
            return

        for line in stdout.strip().splitlines():
            host = line.strip()
            if host:
                await self.save_asset(target_id, "subdomain", host, "amass_active")