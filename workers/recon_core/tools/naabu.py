"""Naabu wrapper — fast port scanning."""

import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, get_session

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Naabu(ReconTool):
    name = "naabu"
    weight_class = WeightClass.HEAVY

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "naabu", "-list", self._input_file or "/dev/null",
            "-json", "-top-ports", "1000", "-silent",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ip = data.get("ip", data.get("host", ""))
                port = data.get("port")
                if ip and port is not None:
                    results.append({"ip": ip, "port": int(port)})
            except (json.JSONDecodeError, ValueError):
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file of live hosts."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["ip", "domain"]),
            )
            result = await session.execute(stmt)
            hosts = [row[0] for row in result.all()]

        if not hosts:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(hosts))
            self._input_file = f.name

        try:
            return await super().execute(
                target, scope_manager, target_id, container_name, headers
            )
        finally:
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
