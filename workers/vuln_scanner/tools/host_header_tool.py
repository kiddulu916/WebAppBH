"""HostHeaderTool -- Host header injection detection via direct HTTP requests."""

from __future__ import annotations

import os

import aiohttp

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("host-header-tool")

HOST_HEADER_TIMEOUT = int(os.environ.get("HOST_HEADER_TIMEOUT", "10"))

# Paths commonly associated with password reset functionality
RESET_PATHS = [
    "/reset-password",
    "/forgot-password",
    "/password/reset",
    "/account/recover",
    "/auth/reset",
]

# Internal IP for routing SSRF test
INTERNAL_IP = "127.0.0.1"

# Canary value used to detect reflection
CANARY_HOST = "evil.attacker-controlled.com"


class HostHeaderTool(VulnScanTool):
    """Host header injection detection using direct HTTP requests."""

    name = "host_header"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Test implementations
    # ------------------------------------------------------------------

    async def _test_password_reset_poisoning(
        self, session: aiohttp.ClientSession, url: str, headers: dict | None,
    ) -> str | None:
        """Test 1: Password reset poisoning with manipulated Host header."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in RESET_PATHS:
            test_url = f"{base_url}{path}"
            test_headers = dict(headers or {})
            test_headers["Host"] = CANARY_HOST
            try:
                async with session.get(
                    test_url,
                    headers=test_headers,
                    timeout=aiohttp.ClientTimeout(total=HOST_HEADER_TIMEOUT),
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    body = await resp.text()
                    # Check if our canary host is reflected in the response
                    if CANARY_HOST in body:
                        return (
                            f"Password reset poisoning: Host header '{CANARY_HOST}' "
                            f"reflected in response at {test_url} (status={resp.status})"
                        )
                    # Check Location header for reflection
                    location = resp.headers.get("Location", "")
                    if CANARY_HOST in location:
                        return (
                            f"Password reset poisoning: Host header '{CANARY_HOST}' "
                            f"reflected in Location header at {test_url}"
                        )
            except (aiohttp.ClientError, OSError, TimeoutError):
                continue
        return None

    async def _test_cache_poisoning(
        self, session: aiohttp.ClientSession, url: str, headers: dict | None,
    ) -> str | None:
        """Test 2: Web cache poisoning via X-Forwarded-Host."""
        test_headers = dict(headers or {})
        test_headers["X-Forwarded-Host"] = CANARY_HOST
        try:
            async with session.get(
                url,
                headers=test_headers,
                timeout=aiohttp.ClientTimeout(total=HOST_HEADER_TIMEOUT),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                body = await resp.text()
                if CANARY_HOST in body:
                    return (
                        f"Cache poisoning: X-Forwarded-Host '{CANARY_HOST}' "
                        f"reflected in response at {url} (status={resp.status})"
                    )
                # Check all response headers for reflection
                for hdr_name, hdr_val in resp.headers.items():
                    if CANARY_HOST in hdr_val:
                        return (
                            f"Cache poisoning: X-Forwarded-Host '{CANARY_HOST}' "
                            f"reflected in {hdr_name} header at {url}"
                        )
        except (aiohttp.ClientError, OSError, TimeoutError):
            pass
        return None

    async def _test_routing_ssrf(
        self, session: aiohttp.ClientSession, url: str, headers: dict | None,
    ) -> str | None:
        """Test 3: Routing-based SSRF via Host header pointing to internal IP."""
        test_headers = dict(headers or {})
        test_headers["Host"] = INTERNAL_IP
        try:
            async with session.get(
                url,
                headers=test_headers,
                timeout=aiohttp.ClientTimeout(total=HOST_HEADER_TIMEOUT),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                body = await resp.text()
                # If we get a different response than expected, it may indicate SSRF
                if resp.status == 200 and len(body) > 0:
                    # Check if the response contains internal-only content indicators
                    low_body = body.lower()
                    internal_indicators = [
                        "internal", "admin", "dashboard", "localhost",
                        "private", "intranet", "management",
                    ]
                    for indicator in internal_indicators:
                        if indicator in low_body:
                            return (
                                f"Routing SSRF: Host header '{INTERNAL_IP}' "
                                f"returned internal content ('{indicator}' found) at {url}"
                            )
        except (aiohttp.ClientError, OSError, TimeoutError):
            pass
        return None

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
            log.info("Skipping host_header -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        # Collect URLs to test
        urls_to_test: list[tuple[int | None, str]] = []

        if triaged_findings:
            # -- Stage 2: test specific URLs from triaged findings --
            for _vuln_id, asset_id, _severity, _title, poc in triaged_findings:
                target_url = poc or ""
                if target_url.startswith("http"):
                    urls_to_test.append((asset_id, target_url))

        elif scan_all:
            # -- Stage 3: test all live URLs --
            live_urls = await self._get_live_urls(target_id)
            for asset_id, domain in live_urls:
                url = f"https://{domain}"
                if await self._has_confirmed_vuln(target_id, asset_id, "host header"):
                    log.debug("Skipping %s -- already confirmed host header vuln", url)
                    continue
                urls_to_test.append((asset_id, url))
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        async with aiohttp.ClientSession() as session:
            for asset_id, url in urls_to_test:
                async with sem:
                    results: list[str] = []

                    # Run all 3 test types
                    result = await self._test_password_reset_poisoning(session, url, headers)
                    if result:
                        results.append(result)

                    result = await self._test_cache_poisoning(session, url, headers)
                    if result:
                        results.append(result)

                    result = await self._test_routing_ssrf(session, url, headers)
                    if result:
                        results.append(result)

                if results:
                    stats["found"] += len(results)
                    stats["in_scope"] += len(results)
                    poc_text = "\n".join(results)

                    if triaged_findings:
                        # Update the matching triaged finding
                        for vuln_id, _aid, severity, title, _poc in triaged_findings:
                            if _aid == asset_id:
                                await self._update_vulnerability(
                                    vuln_id=vuln_id,
                                    severity=severity,
                                    poc=f"host_header confirmed:\n{poc_text}",
                                    source_tool="host_header",
                                    description=f"Host header injection confirmed: {title}",
                                )
                                stats["new"] += 1
                                break
                    else:
                        for finding in results:
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title=f"Host Header Injection - {url}",
                                description=finding,
                                poc=poc_text,
                            )
                            stats["new"] += 1
                    log.info("host_header found %d issues at %s", len(results), url)

        await self.update_tool_state(target_id, container_name)
        log.info("host_header complete", extra=stats)
        return stats
