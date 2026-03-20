"""NaabuTool -- Stage 1 fast port discovery."""

from __future__ import annotations

import json

from sqlalchemy import select

from lib_webbh import Asset, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("naabu-tool")

NAABU_TIMEOUT = 300


class NaabuTool(NetworkTestTool):
    """Fast SYN scan via naabu to discover open ports."""

    name = "naabu"
    weight_class = WeightClass.LIGHT

    def build_command(self, host: str) -> list[str]:
        """Build the naabu CLI command."""
        return [
            "naabu",
            "-host", host,
            "-json",
            "-silent",
            "-rate", "1000",
        ]

    def parse_output(self, raw: str) -> list[dict]:
        """Parse naabu JSON-lines output into list of {host, port} dicts."""
        if not raw.strip():
            return []
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "host" in entry and "port" in entry:
                    results.append(entry)
            except json.JSONDecodeError:
                continue
        return results

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping naabu -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        # Get all IP/domain assets for this target
        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["domain", "ip"]),
            )
            result = await session.execute(stmt)
            assets = list(result.scalars().all())

        if not assets:
            log.warning("No domain/ip assets found — skipping naabu")
            return stats

        for asset in assets:
            host = asset.asset_value
            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                log.debug(f"Skipping out-of-scope host: {host}")
                continue

            cmd = self.build_command(host)
            try:
                raw = await self.run_subprocess(cmd, timeout=NAABU_TIMEOUT)
            except Exception as exc:
                log.error(f"naabu failed for {host}: {exc}")
                continue

            entries = self.parse_output(raw)
            stats["found"] += len(entries)
            stats["in_scope"] += len(entries)

            for entry in entries:
                port = entry["port"]
                _, is_new = await self._save_location(
                    asset_id=asset.id,
                    port=port,
                    protocol="tcp",
                    state="open",
                )
                if is_new:
                    stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("naabu complete", extra=stats)
        return stats
