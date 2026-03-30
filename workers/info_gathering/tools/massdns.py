# workers/info_gathering/tools/massdns.py
"""Massdns wrapper — high-performance DNS resolver."""

import tempfile
import os

from workers.info_gathering.base_tool import InfoGatheringTool


class Massdns(InfoGatheringTool):
    """DNS resolution using Massdns."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        # Read subdomains from DB
        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["subdomain", "domain"]),
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            input_file = f.name

        try:
            cmd = ["massdns", "-r", "/app/workers/info_gathering/resolvers.txt",
                   "-t", "A", "-o", "S", input_file]
            stdout = await self.run_subprocess(cmd, timeout=300)

            for line in stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    hostname = parts[0].rstrip(".")
                    ip = parts[2]
                    await self.save_asset(target_id, "ip", ip, "massdns")
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)