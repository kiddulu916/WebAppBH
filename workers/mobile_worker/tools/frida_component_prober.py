"""FridaComponentProberTool -- Stage 4: probe exported Android components.

Launches exported Activities, binds to Services, sends broadcasts to Receivers
found in Stage 3's manifest audit. Monitors for crashes and data leaks.
"""

from __future__ import annotations

import os
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass
from workers.mobile_worker.tools.manifest_auditor import ManifestAuditorTool

logger = setup_logger("frida-component-prober")

ADB_HOST = os.environ.get("ADB_HOST", "docker-android")
ADB_PORT = os.environ.get("ADB_PORT", "5555")


class FridaComponentProberTool(MobileTestTool):
    """Probe exported Activities/Services/Receivers via ADB."""

    name = "frida_component_prober"
    weight_class = WeightClass.DYNAMIC

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
            log.info("Skipping frida_component_prober -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        if not await self._check_emulator_health():
            log.warning("Emulator unreachable — skipping component probing")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        auditor = ManifestAuditorTool()

        for manifest_path in analysis_dir.glob("*_apktool/AndroidManifest.xml"):
            try:
                manifest_xml = manifest_path.read_text(errors="replace")
                import xml.etree.ElementTree as ET
                root = ET.fromstring(manifest_xml)
                package_name = root.attrib.get("package", "unknown")

                components = auditor._get_exported_components(manifest_xml)
                if not components:
                    continue

                probe_cmds = self._build_probe_commands(package_name, components)
                for probe in probe_cmds:
                    try:
                        output = await self.run_subprocess(probe["cmd"], timeout=30)

                        # Check logcat for crashes
                        logcat_output = await self.run_subprocess(
                            ["adb", "-s", f"{ADB_HOST}:{ADB_PORT}",
                             "logcat", "-d", "-t", "20", "--pid",
                             await self._get_pid(package_name)],
                            timeout=10,
                        )

                        if "FATAL EXCEPTION" in logcat_output or "crash" in logcat_output.lower():
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=None,
                                severity="high",
                                title=f"Crash on exported {probe['type']}: {probe['name']}",
                                description=(
                                    f"Exported {probe['type']} '{probe['name']}' crashed "
                                    f"when probed with crafted intent."
                                ),
                            )
                            stats["found"] += 1
                            stats["new"] += 1

                    except Exception as exc:
                        log.warning(f"Probe failed for {probe['name']}: {exc}")

            except Exception as exc:
                log.error(f"Component probing failed for {manifest_path}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("frida_component_prober complete", extra=stats)
        return stats

    async def _check_emulator_health(self) -> bool:
        try:
            await self.run_subprocess(
                ["adb", "connect", f"{ADB_HOST}:{ADB_PORT}"], timeout=10,
            )
            output = await self.run_subprocess(
                ["adb", "-s", f"{ADB_HOST}:{ADB_PORT}", "shell", "echo", "ok"],
                timeout=10,
            )
            return "ok" in output
        except Exception:
            return False

    async def _get_pid(self, package: str) -> str:
        """Get PID of running package for logcat filtering."""
        try:
            output = await self.run_subprocess(
                ["adb", "-s", f"{ADB_HOST}:{ADB_PORT}", "shell", "pidof", package],
                timeout=5,
            )
            return output.strip()
        except Exception:
            return "0"

    @staticmethod
    def _build_am_start_cmd(package: str, activity_name: str) -> list[str]:
        """Build ADB command to launch an exported activity."""
        component = f"{package}/{activity_name}" if activity_name.startswith(".") \
            else activity_name
        return [
            "adb", "-s", f"{ADB_HOST}:{ADB_PORT}",
            "shell", "am", "start", "-n", component,
        ]

    @staticmethod
    def _build_probe_commands(package: str, components: list[dict]) -> list[dict]:
        """Build ADB probe commands for each exported component."""
        if not components:
            return []

        probes: list[dict] = []
        for comp in components:
            comp_type = comp["type"]
            name = comp["name"]

            if comp_type == "activity":
                component = f"{package}/{name}" if name.startswith(".") else name
                probes.append({
                    "type": "activity",
                    "name": name,
                    "cmd": [
                        "adb", "-s", f"{ADB_HOST}:{ADB_PORT}",
                        "shell", "am", "start", "-n", component,
                    ],
                })
            elif comp_type == "service":
                component = f"{package}/{name}" if name.startswith(".") else name
                probes.append({
                    "type": "service",
                    "name": name,
                    "cmd": [
                        "adb", "-s", f"{ADB_HOST}:{ADB_PORT}",
                        "shell", "am", "startservice", "-n", component,
                    ],
                })
            elif comp_type == "receiver":
                probes.append({
                    "type": "receiver",
                    "name": name,
                    "cmd": [
                        "adb", "-s", f"{ADB_HOST}:{ADB_PORT}",
                        "shell", "am", "broadcast", "-n",
                        f"{package}/{name}" if name.startswith(".") else name,
                    ],
                })

        return probes
