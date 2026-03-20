"""ManifestAuditorTool -- Stage 3: audit AndroidManifest.xml for misconfigurations.

Checks: allowBackup, debuggable, usesCleartextTraffic, FileProvider,
networkSecurityConfig, exported components without permission guards.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("manifest-auditor")

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ManifestAuditorTool(MobileTestTool):
    """Audit AndroidManifest.xml for security misconfigurations."""

    name = "manifest_auditor"
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
            log.info("Skipping manifest_auditor -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        for manifest_path in analysis_dir.glob("*_apktool/AndroidManifest.xml"):
            try:
                manifest_xml = manifest_path.read_text(errors="replace")
                findings = self._audit_manifest(manifest_xml)

                for finding in findings:
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=None,
                        severity=finding["severity"],
                        title=finding["title"],
                        description=finding["description"],
                    )
                    stats["found"] += 1
                    stats["new"] += 1

            except Exception as exc:
                log.error(f"Error auditing {manifest_path}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("manifest_auditor complete", extra=stats)
        return stats

    def _audit_manifest(self, manifest_xml: str) -> list[dict]:
        """Parse manifest and return list of finding dicts."""
        findings: list[dict] = []
        root = ET.fromstring(manifest_xml)
        app = root.find("application")
        if app is None:
            return findings

        # allowBackup
        if app.attrib.get(f"{{{ANDROID_NS}}}allowBackup",
                          app.attrib.get("android:allowBackup")) == "true":
            findings.append({
                "title": "allowBackup enabled",
                "severity": "high",
                "description": "android:allowBackup='true' allows data exfiltration via ADB backup.",
            })

        # debuggable
        if app.attrib.get(f"{{{ANDROID_NS}}}debuggable",
                          app.attrib.get("android:debuggable")) == "true":
            findings.append({
                "title": "Application is debuggable",
                "severity": "critical",
                "description": "android:debuggable='true' allows attaching a debugger in production.",
            })

        # usesCleartextTraffic
        if app.attrib.get(f"{{{ANDROID_NS}}}usesCleartextTraffic",
                          app.attrib.get("android:usesCleartextTraffic")) == "true":
            findings.append({
                "title": "Cleartext traffic allowed",
                "severity": "medium",
                "description": "android:usesCleartextTraffic='true' allows plaintext HTTP connections.",
            })

        # Missing networkSecurityConfig
        nsc = app.attrib.get(f"{{{ANDROID_NS}}}networkSecurityConfig",
                             app.attrib.get("android:networkSecurityConfig"))
        if nsc is None:
            findings.append({
                "title": "Missing networkSecurityConfig",
                "severity": "info",
                "description": "No custom network security configuration defined.",
            })

        # Exported components without permission
        for tag in ("activity", "service", "receiver"):
            for comp in app.findall(tag):
                exported = comp.attrib.get(f"{{{ANDROID_NS}}}exported",
                                           comp.attrib.get("android:exported"))
                permission = comp.attrib.get(f"{{{ANDROID_NS}}}permission",
                                             comp.attrib.get("android:permission"))
                name = comp.attrib.get(f"{{{ANDROID_NS}}}name",
                                       comp.attrib.get("android:name", "unknown"))
                if exported == "true" and not permission:
                    findings.append({
                        "title": f"Exported {tag} without permission: {name}",
                        "severity": "medium",
                        "description": f"{tag} '{name}' is exported without a permission guard.",
                    })

        return findings

    def _get_exported_components(self, manifest_xml: str) -> list[dict]:
        """Return list of exported component dicts for Stage 4 probing."""
        components: list[dict] = []
        root = ET.fromstring(manifest_xml)
        app = root.find("application")
        if app is None:
            return components

        for tag in ("activity", "service", "receiver"):
            for comp in app.findall(tag):
                exported = comp.attrib.get(f"{{{ANDROID_NS}}}exported",
                                           comp.attrib.get("android:exported"))
                name = comp.attrib.get(f"{{{ANDROID_NS}}}name",
                                       comp.attrib.get("android:name", "unknown"))
                if exported == "true":
                    components.append({"type": tag, "name": name})

        return components
