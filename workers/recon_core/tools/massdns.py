"""Massdns wrapper — high-performance DNS resolution."""

import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, get_session

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass

RESOLVERS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "resolvers.txt"
)


class Massdns(ReconTool):
    name = "massdns"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "massdns", "-r", RESOLVERS_PATH, "-t", "A",
            "-o", "S", "-w", "/dev/stdout",
            self._input_file or "/dev/null",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "A":
                domain = parts[0].rstrip(".")
                results.append(domain)
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file of domains before running."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(domains))
            self._input_file = f.name

        try:
            return await super().execute(
                target, scope_manager, target_id, container_name, headers
            )
        finally:
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
