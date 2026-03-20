"""DeeplinkAnalyzerTool -- Stage 3: analyze deeplinks and URL schemes.

Android: parse intent-filter elements for custom schemes and host/path.
iOS: parse CFBundleURLTypes and associated domains from MobSF report.
Flags sensitive paths (login, payment, account linking).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("deeplink-analyzer")

ANDROID_NS = "http://schemas.android.com/apk/res/android"

SENSITIVE_KEYWORDS = {
    "login", "signin", "sign-in", "auth", "oauth",
    "payment", "pay", "checkout", "purchase",
    "account", "profile", "settings", "admin",
    "transfer", "withdraw", "link", "callback",
    "password", "reset", "verify", "confirm",
}


class DeeplinkAnalyzerTool(MobileTestTool):
    """Analyze deeplinks and URL schemes for both platforms."""

    name = "deeplink_analyzer"
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
            log.info("Skipping deeplink_analyzer -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        # Android manifests
        for manifest_path in analysis_dir.glob("*_apktool/AndroidManifest.xml"):
            try:
                manifest_xml = manifest_path.read_text(errors="replace")
                deeplinks = self._parse_android_deeplinks(manifest_xml)
                for dl in deeplinks:
                    host = dl.get("host", "")
                    path = dl.get("path", "")
                    severity = "high" if self._is_sensitive_path(host) or self._is_sensitive_path(path) else "medium"
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=None,
                        severity=severity,
                        title=f"Deeplink: {dl['scheme']}://{host}{path}",
                        description=(
                            f"Custom scheme '{dl['scheme']}' handles "
                            f"host='{host}' path='{path}'. "
                            f"autoVerify={dl.get('auto_verify', 'false')}"
                        ),
                    )
                    stats["found"] += 1
                    stats["new"] += 1
            except Exception as exc:
                log.error(f"Error parsing deeplinks from {manifest_path}: {exc}")

        # iOS MobSF reports
        for report_file in analysis_dir.glob("*_mobsf.json"):
            try:
                with open(report_file) as f:
                    report = json.load(f)
                if report.get("platform", "") != "ios" and \
                   not report.get("file_name", "").endswith(".ipa"):
                    continue
                ios_deeplinks = self._parse_ios_deeplinks(report)
                for dl in ios_deeplinks:
                    severity = "high" if self._is_sensitive_path(dl.get("value", "")) else "medium"
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=None,
                        severity=severity,
                        title=f"iOS {dl['type']}: {dl['value']}",
                        description=f"iOS deeplink: {dl['type']} = {dl['value']}",
                    )
                    stats["found"] += 1
                    stats["new"] += 1
            except Exception as exc:
                log.error(f"Error parsing iOS deeplinks from {report_file}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("deeplink_analyzer complete", extra=stats)
        return stats

    @staticmethod
    def _parse_android_deeplinks(manifest_xml: str) -> list[dict]:
        """Extract deeplink info from Android intent-filter elements."""
        deeplinks: list[dict] = []
        root = ET.fromstring(manifest_xml)

        for activity in root.findall(".//activity"):
            for intent_filter in activity.findall("intent-filter"):
                # Check for VIEW action
                actions = intent_filter.findall("action")
                has_view = any(
                    a.attrib.get(f"{{{ANDROID_NS}}}name",
                                 a.attrib.get("android:name", ""))
                    == "android.intent.action.VIEW"
                    for a in actions
                )
                if not has_view:
                    continue

                auto_verify = intent_filter.attrib.get(
                    f"{{{ANDROID_NS}}}autoVerify",
                    intent_filter.attrib.get("android:autoVerify", "false"),
                )

                for data in intent_filter.findall("data"):
                    scheme = data.attrib.get(f"{{{ANDROID_NS}}}scheme",
                                             data.attrib.get("android:scheme", ""))
                    host = data.attrib.get(f"{{{ANDROID_NS}}}host",
                                           data.attrib.get("android:host", ""))
                    path = data.attrib.get(f"{{{ANDROID_NS}}}path",
                                           data.attrib.get("android:path", ""))
                    path_prefix = data.attrib.get(f"{{{ANDROID_NS}}}pathPrefix",
                                                  data.attrib.get("android:pathPrefix", ""))
                    if scheme:
                        deeplinks.append({
                            "scheme": scheme,
                            "host": host,
                            "path": path or path_prefix,
                            "auto_verify": auto_verify,
                        })

        return deeplinks

    @staticmethod
    def _parse_ios_deeplinks(report: dict) -> list[dict]:
        """Extract iOS URL schemes and associated domains from MobSF report."""
        deeplinks: list[dict] = []

        for scheme in report.get("url_schemes", []):
            deeplinks.append({"type": "url_scheme", "value": scheme})

        entitlements = report.get("entitlements", {})
        if isinstance(entitlements, dict):
            domains = entitlements.get("com.apple.developer.associated-domains", [])
            if isinstance(domains, list):
                for domain in domains:
                    deeplinks.append({"type": "associated_domain", "value": str(domain)})

        return deeplinks

    @staticmethod
    def _is_sensitive_path(path: str) -> bool:
        """Check if a path/host contains sensitive keywords."""
        lower = path.lower()
        return any(kw in lower for kw in SENSITIVE_KEYWORDS)
