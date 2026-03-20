"""MsfCheckTool -- Stage 4 safe exploit verification via Metasploit check."""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import yaml

from sqlalchemy import select

from lib_webbh import Asset, Vulnerability, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("msf-check-tool")

MSFRPC_HOST = os.environ.get("MSFRPC_HOST", "127.0.0.1")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class MsfCheckTool(NetworkTestTool):
    """Safe exploit verification using Metasploit's check command only."""

    name = "msf_check"
    weight_class = WeightClass.HEAVY

    def _load_mappings(self) -> dict:
        """Load CVE-to-MSF module mappings from YAML."""
        map_path = MAPPINGS_DIR / "cve_to_msf.yaml"
        try:
            with open(map_path) as f:
                return yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            return {}

    def find_modules_for_cves(
        self,
        cves: list[str],
        oos_attacks: list[str] | None = None,
    ) -> list[dict]:
        """Match CVEs to MSF modules, filtering out excluded and DoS modules."""
        mappings = self._load_mappings()
        oos = set(oos_attacks or [])
        matches = []
        for cve in cves:
            info = mappings.get(cve)
            if not info:
                continue
            module_path = info["module"]
            # Never run DoS modules regardless of oos_attacks config
            if "/dos/" in module_path:
                continue
            if module_path in oos:
                continue
            matches.append({"cve": cve, **info})
        return matches

    def _get_msf_client(self):
        """Create and return an MsfRpcClient connection."""
        from pymetasploit3.msfrpc import MsfRpcClient

        return MsfRpcClient(
            MSFRPC_PASS, server=MSFRPC_HOST, port=MSFRPC_PORT, ssl=False,
        )

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
            log.info("Skipping msf_check -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}
        oos_attacks = kwargs.get("oos_attacks", [])

        # Get CVEs already found by NmapTool
        async with get_session() as session:
            stmt = select(Vulnerability).where(
                Vulnerability.target_id == target_id,
                Vulnerability.source_tool == "nmap",
                Vulnerability.title.ilike("%CVE-%"),
            )
            result = await session.execute(stmt)
            nmap_vulns = list(result.scalars().all())

        if not nmap_vulns:
            log.info("No CVEs from nmap to verify")
            return stats

        # Extract CVE IDs from vulnerability titles
        cve_to_asset: dict[str, int | None] = {}
        for vuln in nmap_vulns:
            for cve in _CVE_RE.findall(vuln.title):
                cve_to_asset[cve] = vuln.asset_id

        modules = self.find_modules_for_cves(
            list(cve_to_asset.keys()), oos_attacks=oos_attacks,
        )
        if not modules:
            log.info("No matching MSF modules for discovered CVEs")
            return stats

        # Connect to msfrpcd (blocking call — run in thread)
        try:
            client = await asyncio.to_thread(self._get_msf_client)
        except Exception as exc:
            log.error(f"Failed to connect to msfrpcd: {exc}")
            return stats

        for mod_info in modules:
            asset_id = cve_to_asset.get(mod_info["cve"])
            if not asset_id:
                continue

            host = await self._get_asset_ip(asset_id)
            if not host:
                continue

            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                log.debug(f"Skipping out-of-scope host: {host}")
                continue

            module_path = mod_info["module"]
            ports = mod_info.get("ports", [])

            try:
                def _run_check():
                    exploit = client.modules.use("exploit", module_path)
                    exploit["RHOSTS"] = host
                    if ports:
                        exploit["RPORT"] = ports[0]
                    return exploit.check()

                check_result = await asyncio.to_thread(_run_check)
                result_str = str(check_result) if check_result else ""

                if "vulnerable" in result_str.lower():
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1

                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="critical",
                        title=f"Exploitable — {mod_info['cve']}",
                        description=(
                            f"Metasploit check confirmed {host} is vulnerable "
                            f"to {mod_info['cve']} via {module_path}"
                        ),
                        poc=(
                            f"msf> use {module_path}\n"
                            f"msf> set RHOSTS {host}\n"
                            f"msf> check\n"
                            f"Result: {result_str[:500]}"
                        ),
                    )

            except Exception as exc:
                log.error(f"MSF check failed for {mod_info['cve']}: {exc}")
                continue

        await self.update_tool_state(target_id, container_name)
        log.info("msf_check complete", extra=stats)
        return stats
