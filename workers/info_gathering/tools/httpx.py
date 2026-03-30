# workers/info_gathering/tools/httpx.py
"""Httpx wrapper — HTTP probing and technology detection."""

import json
import tempfile
import os

from workers.info_gathering.base_tool import InfoGatheringTool


class Httpx(InfoGatheringTool):
    """HTTP probing and technology detection using Httpx."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            input_file = f.name

        try:
            cmd = [
                "httpx", "-l", input_file,
                "-json", "-silent", "-status-code", "-title",
                "-tech-detect", "-follow-redirects",
            ]
            stdout = await self.run_subprocess(cmd)

            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    await self.save_observation(
                        target_id, "http_probe",
                        {
                            "url": data.get("url", ""),
                            "status_code": data.get("status_code"),
                            "title": data.get("title", ""),
                            "tech": data.get("tech", []),
                        },
                        "httpx"
                    )
                except json.JSONDecodeError:
                    continue
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)