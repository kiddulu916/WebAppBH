# workers/error_handling/tools/stack_trace_detector.py
"""Stack trace detection tool — searches for stack trace disclosures."""

import asyncio
import aiohttp
from lib_webbh.scope import ScopeManager
from workers.error_handling.base_tool import ErrorHandlingTool


class StackTraceDetector(ErrorHandlingTool):
    """Detect stack trace disclosures in various sources."""

    async def execute(self, target_id: int, **kwargs):
        """Execute stack trace detection against target."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        # Get all URL assets in scope
        async with aiohttp.ClientSession() as session:
            urls = await self._get_url_assets(target_id, scope_manager)

            for asset_id, url in urls:
                await self._scan_url_for_stack_traces(session, target_id, asset_id, url)

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

    async def _scan_url_for_stack_traces(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, base_url: str):
        """Scan a URL for stack trace disclosures using various techniques."""

        # Test various error-triggering inputs
        stack_trace_payloads = [
            # Common error triggers
            "?debug=true",
            "?trace=1",
            "?error=1",
            "?exception=true",

            # File inclusion attempts
            "?file=php://filter/convert.base64-encode/resource=index.php",
            "?page=../../../../var/log/apache2/error.log",

            # Debug parameters
            "?show_errors=1",
            "?display_errors=1",
            "?phpinfo=1",

            # ASP.NET debug
            "?ASP.NET_SessionId=debug",
            "?trace.axd",

            # Java debug
            "?debug=true&verbose=1",

            # Ruby on Rails
            "?action=show&controller=rails/info/properties",

            # Application-specific
            "?stacktrace=1",
            "?backtrace=true",
            "?dev=true",
        ]

        for payload in stack_trace_payloads:
            try:
                test_url = base_url + payload
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    response_body = await resp.text()

                    # Extract and analyze stack traces
                    stack_traces = self.extract_stack_trace(response_body)
                    if stack_traces:
                        for trace in stack_traces:
                            framework = trace.get("framework", "Unknown")
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title=f"Stack Trace Disclosure ({framework})",
                                description=f"Stack trace leaked in {framework} framework at {test_url}. File: {trace.get('file', 'N/A')}, Line: {trace.get('line', 'N/A')}",
                                poc=test_url,
                                evidence=str(trace),
                                vuln_type="information_disclosure",
                            )

                    # Also check response headers for debug info
                    debug_headers = [
                        "x-debug-token",
                        "x-error-details",
                        "x-stack-trace",
                        "x-exception",
                    ]

                    for header_name in debug_headers:
                        if header_name in resp.headers:
                            header_value = resp.headers[header_name]
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title="Debug Information in HTTP Headers",
                                description=f"Debug information disclosed in HTTP header '{header_name}' at {test_url}",
                                poc=test_url,
                                evidence=f"{header_name}: {header_value}",
                                vuln_type="information_disclosure",
                            )

            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

        # Additional check: try to access common debug/error endpoints
        debug_endpoints = [
            "/debug",
            "/trace",
            "/errors",
            "/stacktrace",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
            "/trace.axd",
            "/elmah.axd",
            "/rails/info",
        ]

        for endpoint in debug_endpoints:
            try:
                # Try both with and without trailing slash
                for test_url in [base_url.rstrip('/') + endpoint, base_url + endpoint]:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:  # Debug endpoint accessible
                            response_body = await resp.text()

                            # Check for debug content
                            debug_indicators = [
                                "stack trace", "traceback", "debug", "error log",
                                "phpinfo", "server status", "environment variables"
                            ]

                            lower_body = response_body.lower()
                            if any(indicator in lower_body for indicator in debug_indicators):
                                await self.save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="Accessible Debug Endpoint",
                                    description=f"Debug information accessible at {test_url}",
                                    poc=test_url,
                                    evidence=response_body[:500],
                                    vuln_type="information_disclosure",
                                )

            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue