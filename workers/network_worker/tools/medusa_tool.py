"""MedusaTool -- Stage 3 default credential testing."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from lib_webbh import get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("medusa-tool")

MEDUSA_TIMEOUT = 120

_SUCCESS_RE = re.compile(
    r"ACCOUNT FOUND:.*Host:\s*(\S+).*User:\s*(\S+).*Password:\s*(\S+).*\[SUCCESS\]"
)

# Map service names (from nmap/banner_grab) to Medusa module names
SERVICE_TO_MEDUSA_MODULE: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
    "mysql": "mysql",
    "postgresql": "postgres",
    "redis": "redis",
    "mongodb": "mongodb",
    "smb": "smbnt",
    "microsoft-ds": "smbnt",
    "pop3": "pop3",
    "imap": "imap",
}

WORDLISTS_DIR = Path(__file__).resolve().parent.parent / "wordlists"


class MedusaTool(NetworkTestTool):
    """Default credential testing via Medusa with strict rate limiting."""

    name = "medusa"
    weight_class = WeightClass.MEDIUM

    def _load_creds(self, service: str) -> list[tuple[str, str]]:
        """Load credential pairs for a service from YAML."""
        creds_path = WORDLISTS_DIR / "default_creds.yaml"
        try:
            with open(creds_path) as f:
                all_creds = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            return []
        pairs = all_creds.get(service, [])
        return [(p[0], p[1]) for p in pairs if len(p) == 2]

    def build_command(
        self,
        host: str,
        port: int,
        module: str,
        user: str,
        password: str,
    ) -> list[str]:
        """Build the medusa CLI command with hardcoded rate limiting."""
        return [
            "medusa",
            "-h", host,
            "-n", str(port),
            "-u", user,
            "-p", password,
            "-M", module,
            "-t", "1",      # single thread — hardcoded safety
            "-w", "2",      # 2-second wait — hardcoded safety
            "-f",           # stop on first success
        ]

    def parse_output(self, raw: str) -> list[dict]:
        """Parse Medusa output for successful logins."""
        results = []
        for match in _SUCCESS_RE.finditer(raw):
            results.append({
                "host": match.group(1),
                "user": match.group(2),
                "password": match.group(3),
            })
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
            log.info("Skipping medusa -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        locations = await self._get_non_http_locations(target_id)
        if not locations:
            log.info("No non-HTTP services to test credentials against")
            return stats

        for loc in locations:
            service = (loc.service or "").lower().split()[0]
            medusa_module = SERVICE_TO_MEDUSA_MODULE.get(service)
            if not medusa_module:
                continue

            host = await self._get_asset_ip(loc.asset_id)
            if not host:
                continue

            creds = self._load_creds(service)
            if not creds:
                creds = self._load_creds(medusa_module)
            if not creds:
                continue

            for user, password in creds:
                cmd = self.build_command(host, loc.port, medusa_module, user, password)
                try:
                    raw = await self.run_subprocess(cmd, timeout=MEDUSA_TIMEOUT)
                except Exception as exc:
                    log.error(f"medusa failed for {host}:{loc.port}: {exc}")
                    continue

                successes = self.parse_output(raw)
                for success in successes:
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=loc.asset_id,
                        severity="high",
                        title=(
                            f"Default Credentials — {service} "
                            f"on port {loc.port}"
                        ),
                        description=(
                            f"Successful login with "
                            f"{success['user']}:{success['password']} "
                            f"on {host}:{loc.port} ({service})"
                        ),
                        poc=(
                            f"medusa -h {host} -n {loc.port} "
                            f"-u {success['user']} -p {success['password']} "
                            f"-M {medusa_module}"
                        ),
                    )

                if successes:
                    break  # Found valid creds, stop testing this service

        await self.update_tool_state(target_id, container_name)
        log.info("medusa complete", extra=stats)
        return stats
