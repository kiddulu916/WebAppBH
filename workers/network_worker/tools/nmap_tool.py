"""NmapTool -- Stage 2 deep service versioning and NSE vuln scanning."""

from __future__ import annotations

import os
import re
import tempfile
import xml.etree.ElementTree as ET

from sqlalchemy import select

from lib_webbh import Asset, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("nmap-tool")

NMAP_TIMEOUT = 600

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class NmapTool(NetworkTestTool):
    """Deep service versioning and NSE vulnerability scanning via nmap."""

    name = "nmap"
    weight_class = WeightClass.MEDIUM

    def build_command(
        self,
        host: str,
        ports: list[int],
        oos_attacks: list[str] | None = None,
        output_file: str = "-",
    ) -> list[str]:
        """Build the nmap CLI command."""
        port_str = ",".join(str(p) for p in ports)
        cmd = [
            "nmap", "-sV", "-sC",
            "--script=vuln",
            "-O",
            "-p", port_str,
            "-oX", output_file,
            host,
        ]
        if oos_attacks:
            exclude_str = ",".join(oos_attacks)
            cmd.insert(
                cmd.index("--script=vuln") + 1,
                f"--script-exclude={exclude_str}",
            )
        return cmd

    def parse_xml(self, xml_str: str) -> list[dict]:
        """Parse nmap XML output into structured host results."""
        results = []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return results

        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            if addr_el is None:
                continue

            host_data = {
                "addr": addr_el.get("addr", ""),
                "ports": [],
                "os_match": None,
                "script_output": "",
            }

            # Parse ports
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    port_data = {
                        "port": int(port_el.get("portid", "0")),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": state_el.get("state", "") if state_el is not None else "",
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                    }

                    # Collect script output for this port
                    scripts = []
                    for script_el in port_el.findall("script"):
                        scripts.append(
                            f"{script_el.get('id', '')}: {script_el.get('output', '')}"
                        )
                    port_data["scripts"] = "\n".join(scripts)

                    host_data["ports"].append(port_data)

            # Parse OS detection
            os_el = host_el.find("os")
            if os_el is not None:
                osmatch = os_el.find("osmatch")
                if osmatch is not None:
                    host_data["os_match"] = osmatch.get("name", "")

            # Collect host-level script output
            hostscript_el = host_el.find("hostscript")
            if hostscript_el is not None:
                scripts = []
                for script_el in hostscript_el.findall("script"):
                    scripts.append(
                        f"{script_el.get('id', '')}: {script_el.get('output', '')}"
                    )
                host_data["script_output"] = "\n".join(scripts)

            results.append(host_data)

        return results

    def extract_cves(self, script_output: str) -> list[str]:
        """Extract CVE identifiers from NSE script output."""
        return list(set(_CVE_RE.findall(script_output)))

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
            log.info("Skipping nmap -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}
        oos_attacks = kwargs.get("oos_attacks", [])

        locations = await self._get_non_http_locations(target_id)
        if not locations:
            log.info("No non-HTTP open ports to scan")
            return stats

        asset_ports: dict[int, list[int]] = {}
        for loc in locations:
            asset_ports.setdefault(loc.asset_id, []).append(loc.port)

        for asset_id, ports in asset_ports.items():
            host = await self._get_asset_ip(asset_id)
            if not host:
                continue

            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                continue

            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
                xml_path = tmp.name

            cmd = self.build_command(
                host, ports, oos_attacks=oos_attacks, output_file=xml_path,
            )

            try:
                await self.run_subprocess(cmd, timeout=NMAP_TIMEOUT)
                with open(xml_path) as f:
                    xml_str = f.read()
            except Exception as exc:
                log.error(f"nmap failed for {host}: {exc}")
                continue
            finally:
                try:
                    os.unlink(xml_path)
                except OSError:
                    pass

            hosts = self.parse_xml(xml_str)
            for host_data in hosts:
                for port_data in host_data["ports"]:
                    stats["found"] += 1
                    stats["in_scope"] += 1

                    service_str = port_data["service"]
                    if port_data["product"]:
                        service_str = port_data["product"]
                        if port_data["version"]:
                            service_str += f" {port_data['version']}"

                    _, is_new = await self._save_location(
                        asset_id=asset_id,
                        port=port_data["port"],
                        protocol=port_data["protocol"],
                        service=service_str,
                        state=port_data["state"],
                    )
                    if is_new:
                        stats["new"] += 1

                    all_scripts = port_data.get("scripts", "")
                    cves = self.extract_cves(all_scripts)
                    for cve in cves:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Vulnerable Service — {cve}",
                            description=(
                                f"{service_str} on port {port_data['port']} "
                                f"flagged by NSE"
                            ),
                            poc=all_scripts[:2000],
                        )

                if host_data.get("os_match"):
                    await self._save_observation_tech_stack(asset_id, {
                        "os_fingerprint": host_data["os_match"],
                        "nmap_scan_source": self.name,
                    })

                if host_data.get("script_output"):
                    host_cves = self.extract_cves(host_data["script_output"])
                    for cve in host_cves:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Host Vulnerability — {cve}",
                            description=(
                                f"Host-level NSE detection on "
                                f"{host_data['addr']}"
                            ),
                            poc=host_data["script_output"][:2000],
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("nmap complete", extra=stats)
        return stats
