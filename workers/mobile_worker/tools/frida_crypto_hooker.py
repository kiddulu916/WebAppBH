"""FridaCryptoHookerTool -- Stage 4: Frida hooks for crypto/SSL/pinning/HTTP.

Hooks javax.crypto, SSLContext, OkHttp CertificatePinner, HttpURLConnection.
All scripts are inline JS. APK only.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("frida-crypto-hooker")

ADB_HOST = os.environ.get("ADB_HOST", "docker-android")
ADB_PORT = os.environ.get("ADB_PORT", "5555")


class FridaCryptoHookerTool(MobileTestTool):
    """Hook crypto/SSL/pinning/HTTP classes via Frida on Android emulator."""

    name = "frida_crypto_hooker"
    weight_class = WeightClass.DYNAMIC

    SCRIPT_TIMEOUT = 60  # seconds per script

    FRIDA_SCRIPT = r"""
Java.perform(function() {
    // Hook Cipher.init
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        var algo = this.getAlgorithm();
        console.log('[HOOK] Cipher.init: algorithm=' + algo);
        return this.init(mode, key);
    };

    // Hook SSLContext.init
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            if (tm != null) {
                console.log('[HOOK] SSLContext.init: custom TrustManager detected');
            }
            return this.init(km, tm, sr);
        };
    } catch(e) {}

    // Hook OkHttp CertificatePinner
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            console.log('[HOOK] CertificatePinner.check: ' + hostname + ' — bypassed');
        };
    } catch(e) {}

    // Hook HttpURLConnection for plaintext HTTP
    try {
        var URL = Java.use('java.net.URL');
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function() {
            var url = this.getURL().toString();
            if (url.startsWith('http://')) {
                console.log('[HOOK] HttpURLConnection: plaintext HTTP to ' + url);
            }
            return this.connect();
        };
    } catch(e) {}
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
            log.info("Skipping frida_crypto_hooker -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        if not await self._check_emulator_health():
            log.warning("Emulator unreachable — skipping dynamic analysis")
            return {"found": 0, "in_scope": 0, "new": 0}

        analysis_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        for apk_path in analysis_dir.glob("*.apk"):
            try:
                # Install APK
                await self.run_subprocess(
                    ["adb", "-s", f"{ADB_HOST}:{ADB_PORT}", "install", "-r", str(apk_path)],
                    timeout=120,
                )

                # Run frida script
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

                # Uninstall APK
                try:
                    await self.run_subprocess(
                        ["adb", "-s", f"{ADB_HOST}:{ADB_PORT}", "uninstall", apk_path.stem],
                        timeout=30,
                    )
                except Exception:
                    pass

            except Exception as exc:
                log.error(f"Frida crypto hook failed for {apk_path.name}: {exc}")

        await self.update_tool_state(target_id, container_name)
        log.info("frida_crypto_hooker complete", extra=stats)
        return stats

    async def _check_emulator_health(self) -> bool:
        """Ping ADB to check emulator reachability."""
        try:
            await self.run_subprocess(
                ["adb", "connect", f"{ADB_HOST}:{ADB_PORT}"],
                timeout=10,
            )
            output = await self.run_subprocess(
                ["adb", "-s", f"{ADB_HOST}:{ADB_PORT}", "shell", "echo", "ok"],
                timeout=10,
            )
            return "ok" in output
        except Exception:
            return False

    async def _run_frida_script(self, package: str, log) -> str:
        """Execute inline Frida script against the package."""
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
            log.warning(f"Frida script timed out or failed for {package}: {exc}")
            return ""
        finally:
            os.unlink(script_path)

    @staticmethod
    def _parse_output(output: str) -> list[dict]:
        """Parse Frida hook output lines into findings."""
        findings: list[dict] = []

        for line in output.splitlines():
            if "[HOOK] Cipher.init:" in line:
                algo = line.split("algorithm=", 1)[-1].strip() if "algorithm=" in line else "unknown"
                weak = any(w in algo.upper() for w in ("DES", "RC4", "MD5", "ECB"))
                if weak:
                    findings.append({
                        "type": "weak_crypto",
                        "severity": "high",
                        "title": f"Weak crypto algorithm: {algo}",
                        "description": f"App uses weak cryptographic algorithm: {algo}",
                    })

            elif "[HOOK] SSLContext.init:" in line:
                findings.append({
                    "type": "ssl_issue",
                    "severity": "high",
                    "title": "Custom TrustManager detected",
                    "description": "SSLContext initialized with custom TrustManager — possible cert validation bypass.",
                })

            elif "[HOOK] CertificatePinner" in line:
                findings.append({
                    "type": "pinning_bypass",
                    "severity": "medium",
                    "title": "Certificate pinning bypassed",
                    "description": line.strip(),
                })

            elif "[HOOK] HttpURLConnection: plaintext" in line:
                url_match = re.search(r"http://\S+", line)
                url = url_match.group(0) if url_match else "unknown"
                findings.append({
                    "type": "plaintext_http",
                    "severity": "high",
                    "title": f"Plaintext HTTP connection: {url}",
                    "description": f"App makes plaintext HTTP request to {url}",
                })

        return findings
