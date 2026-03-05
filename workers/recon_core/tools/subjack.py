"""Subjack wrapper — subdomain takeover detection."""

import asyncio
import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, Alert, Observation, get_session, push_task, setup_logger

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass, get_semaphore

FINGERPRINTS_PATH = os.environ.get(
    "SUBJACK_FINGERPRINTS", "/opt/fingerprints.json"
)


class SubjackTool(ReconTool):
    name = "subjack"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "subjack", "-w", self._input_file or "/dev/null",
            "-t", "50", "-timeout", "30",
            "-o", "/dev/stdout", "-ssl",
            "-a", FINGERPRINTS_PATH,
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("vulnerable"):
                    results.append({
                        "subdomain": data.get("subdomain", ""),
                        "service": data.get("service", ""),
                        "fingerprint": data.get("fingerprint", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file and insert Observation + Alert rows."""
        log = setup_logger("recon-tool").bind(target_id=target_id)

        # Query all discovered domains
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Write temp file
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
                subdomain = item["subdomain"]
                service = item["service"]

                scope_result = scope_manager.is_in_scope(subdomain)
                if not scope_result.in_scope:
                    continue

                async with get_session() as session:
                    # Look up existing Asset
                    stmt = select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == scope_result.normalized,
                    )
                    result = await session.execute(stmt)
                    asset = result.scalar_one_or_none()
                    if asset is None:
                        continue

                    # Insert Observation
                    obs = Observation(
                        asset_id=asset.id,
                        status_code=None,
                        page_title=f"Subdomain takeover: {service}",
                        tech_stack=["subjack:takeover"],
                        headers=None,
                    )
                    session.add(obs)
                    await session.flush()

                    # Insert critical Alert
                    alert = Alert(
                        target_id=target_id,
                        alert_type="critical",
                        message=f"Subdomain takeover possible: {subdomain} → {service} (CNAME dangling)",
                    )
                    session.add(alert)
                    await session.commit()
                    alert_id = alert.id

                # Push alert event to Redis
                await push_task(f"events:{target_id}", {
                    "event": "critical_alert",
                    "alert_id": alert_id,
                    "message": f"Subdomain takeover possible: {subdomain} → {service} (CNAME dangling)",
                })
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
