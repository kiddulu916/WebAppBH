"""BannerGrabTool -- Stage 2 raw banner grab for service identification."""

from __future__ import annotations

import re

from lib_webbh import get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("banner-grab-tool")

SOCAT_TIMEOUT = 10

# Banner patterns for service detection
_SERVICE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh", re.compile(r"^SSH-", re.IGNORECASE)),
    ("ftp", re.compile(
        r"^220[- ].*ftp|^220[- ].*ProFTPD|^220[- ].*vsftpd",
        re.IGNORECASE,
    )),
    ("smtp", re.compile(
        r"^220[- ].*ESMTP|^220[- ].*SMTP|^220[- ].*mail",
        re.IGNORECASE,
    )),
    ("pop3", re.compile(r"^\+OK.*POP3", re.IGNORECASE)),
    ("imap", re.compile(r"^\*\s*OK.*IMAP", re.IGNORECASE)),
    ("ldap", re.compile(r"LDAP|objectClass|0\x84|dn:|cn=", re.IGNORECASE)),
    ("mysql", re.compile(r"mysql|MariaDB", re.IGNORECASE)),
    ("redis", re.compile(r"^\-ERR|^-NOAUTH|^\+PONG|redis", re.IGNORECASE)),
]


class BannerGrabTool(NetworkTestTool):
    """Raw banner grab via socat to identify unrecognized services."""

    name = "banner_grab"
    weight_class = WeightClass.LIGHT

    def detect_service(self, banner: str) -> str | None:
        """Detect service type from a raw banner string."""
        if not banner or not banner.strip():
            return None
        for service_name, pattern in _SERVICE_PATTERNS:
            if pattern.search(banner):
                return service_name
        return None

    def build_command(self, host: str, port: int) -> list[str]:
        """Build socat command for banner grabbing."""
        return [
            "socat", "-T", str(SOCAT_TIMEOUT),
            "-", f"TCP:{host}:{port},connect-timeout={SOCAT_TIMEOUT}",
        ]

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
            log.info("Skipping banner_grab -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        locations = await self._get_non_http_locations(target_id)
        unidentified = [
            loc for loc in locations
            if not loc.service or loc.service in ("unknown", "tcpwrapped", "")
        ]

        ldap_ports = {389, 636}
        ldap_locs = [
            loc for loc in locations
            if loc.port in ldap_ports and loc not in unidentified
        ]
        targets = unidentified + ldap_locs

        if not targets:
            log.info("No unidentified services to banner-grab")
            return stats

        for loc in targets:
            host = await self._get_asset_ip(loc.asset_id)
            if not host:
                continue

            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                log.debug(f"Skipping out-of-scope host: {host}")
                continue

            cmd = self.build_command(host, loc.port)
            try:
                banner = await self.run_subprocess(cmd, timeout=SOCAT_TIMEOUT + 5)
            except Exception:
                continue

            detected = self.detect_service(banner)
            if detected:
                stats["found"] += 1
                stats["in_scope"] += 1
                _, is_new = await self._save_location(
                    asset_id=loc.asset_id,
                    port=loc.port,
                    protocol=loc.protocol or "tcp",
                    service=detected,
                    state="open",
                )
                if is_new:
                    stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("banner_grab complete", extra=stats)
        return stats
