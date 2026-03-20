"""FridaRootDetectorTool -- Stage 4: Frida hooks for root/SafetyNet detection.

Hooks RootBeer, SafetyNet, common root detection patterns.
Reports whether root detection is present and bypassability.
"""

from __future__ import annotations

import os
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("frida-root-detector")

ADB_HOST = os.environ.get("ADB_HOST", "docker-android")
ADB_PORT = os.environ.get("ADB_PORT", "5555")


class FridaRootDetectorTool(MobileTestTool):
    """Hook root/SafetyNet detection paths via Frida, report bypassability."""

    name = "frida_root_detector"
    weight_class = WeightClass.DYNAMIC

    SCRIPT_TIMEOUT = 60

    FRIDA_SCRIPT = r"""
Java.perform(function() {
    // Hook RootBeer
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[HOOK] RootBeer.isRooted() called — bypassed (returned false)');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log('[HOOK] RootBeer.isRootedWithoutBusyBoxCheck() — bypassed');
            return false;
        };
    } catch(e) {}

    // Hook SafetyNet
    try {
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
        SafetyNet.attest.implementation = function(nonce, apiKey) {
            console.log('[HOOK] SafetyNet.attest() intercepted');
            return this.attest(nonce, apiKey);
        };
    } catch(e) {}

    // Hook Runtime for "su" checks (uses exec array overload, not shell)
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        var cmd = cmdArray.join(' ');
        if (cmd.indexOf('su') !== -1) {
            console.log('[HOOK] Runtime.exec: ' + cmd + ' — root check detected');
        }
        return this.exec(cmdArray);
    };

    // Hook File.exists for common root indicators
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('Superuser.apk') !== -1 || path.indexOf('/su') !== -1 ||
            path.indexOf('magisk') !== -1) {
            console.log('[HOOK] File.exists: ' + path + ' — root indicator check');
            return false;
        }
        return this.exists();
    };
});
"""

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
            log.info("Skipping frida_root_detector -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        if not await self._check_emulator_health():
            log.warning("Emulator unreachable — skipping root detection analysis")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        for apk_path in analysis_dir.glob("*.apk"):
            try:
                output = await self._run_frida_script(apk_path.stem, log)
                findings = self._parse_output(output)

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
                log.error(f"Frida root detection failed for {apk_path.name}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("frida_root_detector complete", extra=stats)
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

    async def _run_frida_script(self, package: str, log) -> str:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(self.FRIDA_SCRIPT)
            script_path = f.name
        try:
            output = await self.run_subprocess(
                ["frida", "-U", "-f", package, "-l", script_path, "--no-pause", "-q"],
                timeout=self.SCRIPT_TIMEOUT,
            )
            return output
        except Exception as exc:
            log.warning(f"Frida root detector timed out for {package}: {exc}")
            return ""
        finally:
            os.unlink(script_path)

    @staticmethod
    def _parse_output(output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            if "[HOOK] RootBeer" in line:
                findings.append({
                    "type": "root_detection",
                    "severity": "info",
                    "title": "Root detection (RootBeer) — easily bypassed",
                    "description": line.strip(),
                })
            elif "[HOOK] SafetyNet" in line:
                findings.append({
                    "type": "safetynet",
                    "severity": "info",
                    "title": "SafetyNet attestation intercepted",
                    "description": line.strip(),
                })
            elif "[HOOK] Runtime" in line and "root check" in line:
                findings.append({
                    "type": "root_check",
                    "severity": "info",
                    "title": "Root check via Runtime.exec(su)",
                    "description": line.strip(),
                })
            elif "[HOOK] File.exists" in line and "root indicator" in line:
                findings.append({
                    "type": "root_file_check",
                    "severity": "info",
                    "title": "Root indicator file check — bypassed",
                    "description": line.strip(),
                })
        return findings
