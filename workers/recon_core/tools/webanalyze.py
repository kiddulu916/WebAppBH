"""Webanalyze wrapper — technology fingerprinting via Wappalyzer signatures."""

import asyncio
import json
import os
import tempfile

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from lib_webbh import Asset, Observation, get_session, setup_logger

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Webanalyze(ReconTool):
    name = "webanalyze"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "webanalyze", "-hosts", self._input_file or "/dev/null",
            "-json", "-silent", "-crawl", "1",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                hostname = data.get("hostname", "")
                matches = data.get("matches", [])
                if not hostname or not matches:
                    continue
                techs = [m.get("app_name", "") for m in matches if m.get("app_name")]
                if techs:
                    results.append({"host": hostname, "tech": techs})
            except json.JSONDecodeError:
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to query live domains and write input file."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "domain",
                )
                .join(Observation, Observation.asset_id == Asset.id)
                .where(Observation.status_code.isnot(None))
                .distinct()
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
