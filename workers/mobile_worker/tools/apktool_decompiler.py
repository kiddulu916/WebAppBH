"""ApktoolDecompilerTool -- Stage 1: APK decompilation with apktool + jadx.

Decompiles APK binaries and parses AndroidManifest.xml for metadata.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("apktool-decompiler")

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ApktoolDecompilerTool(MobileTestTool):
    """Decompile APKs with apktool and jadx, parse manifest metadata."""

    name = "apktool_decompiler"
    weight_class = WeightClass.STATIC

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
            log.info("Skipping apktool_decompiler -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        if not analysis_dir.is_dir():
            return stats

        for apk_path in analysis_dir.glob("*.apk"):
            try:
                stem = apk_path.stem
                apktool_out = analysis_dir / f"{stem}_apktool"
                jadx_out = analysis_dir / f"{stem}_jadx"

                # Run apktool
                if not apktool_out.exists():
                    cmd = self._build_apktool_cmd(str(apk_path), str(apktool_out))
                    await self.run_subprocess(cmd)

                # Run jadx
                if not jadx_out.exists():
                    cmd = self._build_jadx_cmd(str(apk_path), str(jadx_out))
                    await self.run_subprocess(cmd)

                # Parse manifest
                manifest_path = apktool_out / "AndroidManifest.xml"
                if manifest_path.exists():
                    manifest_xml = manifest_path.read_text(errors="replace")
                    info = self._parse_manifest(manifest_xml)

                    await self._save_mobile_app(
                        target_id=target_id,
                        platform="android",
                        package_name=info["package_name"],
                        version=info.get("version"),
                        permissions=info.get("permissions"),
                        decompiled_path=str(jadx_out),
                        source_tool=self.name,
                    )
                    stats["found"] += 1
                    stats["new"] += 1

            except Exception as exc:
                log.error(f"Decompilation failed for {apk_path.name}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("apktool_decompiler complete", extra=stats)
        return stats

    @staticmethod
    def _build_apktool_cmd(apk_path: str, output_dir: str) -> list[str]:
        """Build apktool decompile command."""
        return ["apktool", "d", apk_path, "-o", output_dir, "-f"]

    @staticmethod
    def _build_jadx_cmd(apk_path: str, output_dir: str) -> list[str]:
        """Build jadx decompile command."""
        return ["jadx", apk_path, "-d", output_dir, "--no-res"]

    @staticmethod
    def _parse_manifest(manifest_xml: str) -> dict:
        """Parse AndroidManifest.xml and extract metadata."""
        root = ET.fromstring(manifest_xml)
        package_name = root.attrib.get("package", "unknown")
        version = root.attrib.get(f"{{{ANDROID_NS}}}versionName",
                                  root.attrib.get("android:versionName"))

        permissions = []
        for perm in root.findall(".//uses-permission"):
            name = perm.attrib.get(f"{{{ANDROID_NS}}}name",
                                   perm.attrib.get("android:name", ""))
            if name:
                permissions.append(name)

        return {
            "package_name": package_name,
            "version": version,
            "permissions": permissions,
        }
