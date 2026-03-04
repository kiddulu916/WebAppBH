"""Httpx wrapper — HTTP probing and technology detection."""

import asyncio
import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session, setup_logger

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass, get_semaphore


class HttpxTool(ReconTool):
    name = "httpx"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        cmd = [
            "httpx", "-l", self._input_file or "/dev/null",
            "-json", "-silent", "-status-code", "-title",
            "-tech-detect", "-follow-redirects",
        ]
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                    "headers": data.get("header", {}),
                })
            except json.JSONDecodeError:
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file and insert Observation rows."""
        log = setup_logger("recon-tool").bind(target_id=target_id)

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

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            cmd = self.build_command(target, headers)
            try:
                stdout = await self.run_subprocess(cmd)
            except (asyncio.TimeoutError, FileNotFoundError):
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            results = self.parse_output(stdout)
            new_count = 0

            for item in results:
                url = item.get("url", "")
                scope_result = scope_manager.is_in_scope(url)
                if not scope_result.in_scope:
                    continue

                async with get_session() as session:
                    stmt = select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == scope_result.normalized,
                    )
                    result = await session.execute(stmt)
                    asset = result.scalar_one_or_none()
                    if asset is None:
                        continue

                    obs = Observation(
                        asset_id=asset.id,
                        status_code=item.get("status_code"),
                        page_title=item.get("title"),
                        tech_stack=item.get("tech"),
                        headers=item.get("headers"),
                    )
                    session.add(obs)
                    await session.commit()
                    new_count += 1

            return {
                "found": len(results),
                "in_scope": new_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
        finally:
            sem.release()
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
