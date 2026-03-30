# workers/info_gathering/tools/amass_passive.py
"""AmassPassive wrapper — passive subdomain enumeration via Amass."""

from workers.info_gathering.base_tool import InfoGatheringTool


class AmassPassive(InfoGatheringTool):
    """Passive subdomain enumeration using Amass."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["amass", "enum", "-passive", "-d", target.base_domain]
        try:
            stdout = await self.run_subprocess(cmd, timeout=900)
        except Exception:
            return

        for line in stdout.strip().splitlines():
            host = line.strip()
            if host:
                await self.save_asset(target_id, "subdomain", host, "amass_passive")