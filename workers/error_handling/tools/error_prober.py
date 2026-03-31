# workers/error_handling/tools/error_prober.py
"""Error code probing tool — tests for error disclosure vulnerabilities."""

import asyncio
import aiohttp
from lib_webbh.scope import ScopeManager
from workers.error_handling.base_tool import ErrorHandlingTool


class ErrorProber(ErrorHandlingTool):
    """Probe for error disclosure by triggering error conditions."""

    async def execute(self, target_id: int, **kwargs):
        """Execute error probing against target URLs."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        # Get all URL assets in scope
        async with aiohttp.ClientSession() as session:
            urls = await self._get_url_assets(target_id, scope_manager)

            for asset_id, url in urls:
                await self._probe_url_errors(session, target_id, asset_id, url)

    async def _get_url_assets(self, target_id: int, scope_manager: ScopeManager):
        """Get all URL assets for the target."""
        from lib_webbh import get_session, Asset

        urls = []
        async with get_session() as session:
            result = await session.execute(
                f"SELECT id, asset_value FROM assets WHERE target_id = {target_id} AND asset_type = 'url'"
            )
            for row in result:
                asset_id, asset_value = row
                if scope_manager.is_in_scope(asset_value):
                    urls.append((asset_id, asset_value))
        return urls

    async def _probe_url_errors(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, base_url: str):
        """Probe a single URL for error conditions."""
        # Common error-triggering payloads
        error_payloads = [
            # Invalid parameters
            "?invalid_param=test",
            "?id=999999999",  # Non-existent ID
            "?page=-1",  # Negative page
            "?page=999999",  # Very high page

            # SQL injection attempts
            "?id=1'",
            "?id=1 UNION SELECT 1",

            # XSS attempts
            "?search=<script>alert(1)</script>",
            "?input=javascript:alert(1)",

            # Command injection
            "?cmd=;ls",
            "?exec=cat /etc/passwd",

            # Long inputs (buffer overflow attempts)
            "?input=" + "A" * 10000,
            "?data=" + "B" * 5000,

            # Path traversal
            "?file=../../../etc/passwd",
            "?path=....//....//....//etc/passwd",

            # Format string
            "?format=%s%s%s%s",

            # LDAP injection
            "?user=*)(uid=*))(|(uid=*",

            # XML injection
            "?xml=<test></test>",
            "?data=<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
        ]

        for payload in error_payloads:
            try:
                test_url = base_url + payload
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    response_body = await resp.text()

                    # Check for framework error pages
                    framework = self.detect_framework_error_page(response_body)
                    if framework:
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"{framework} Error Page Disclosure",
                            description=f"Framework error page detected for {framework} at {test_url}",
                            poc=test_url,
                            evidence=response_body[:500],  # First 500 chars
                        )

                    # Check for stack traces
                    stack_traces = self.extract_stack_trace(response_body)
                    if stack_traces:
                        for trace in stack_traces:
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title="Stack Trace Disclosure",
                                description=f"Stack trace leaked in {trace.get('framework', 'unknown')} framework at {test_url}",
                                poc=test_url,
                                evidence=str(trace),
                            )

                    # Check for generic error patterns
                    error_indicators = [
                        "error", "exception", "fatal", "warning",
                        "traceback", "debug", "stack", "internal server error"
                    ]

                    lower_body = response_body.lower()
                    if any(indicator in lower_body for indicator in error_indicators):
                        # Additional check: avoid false positives from normal pages
                        if resp.status >= 400 or len(response_body) < 10000:  # Error status or short error response
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="low",
                                title="Potential Error Disclosure",
                                description=f"Potential error information disclosed at {test_url}",
                                poc=test_url,
                                evidence=response_body[:300],
                            )

            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue  # Skip network errors