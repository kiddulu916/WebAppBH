# workers/error_handling/tools/stack_trace_detector.py
"""Stack trace detection tool — searches for stack trace disclosures."""

import asyncio
import aiohttp
from lib_webbh.scope import ScopeManager
from workers.error_handling.base_tool import ErrorHandlingTool


class StackTraceDetector(ErrorHandlingTool):
    """Detect stack trace disclosures in various sources."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        """Execute stack trace detection against target."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return {"found": 0, "vulnerable": 0}

        async with aiohttp.ClientSession() as session:
            urls = await self._get_url_assets(target_id, scope_manager)
            await asyncio.gather(
                *[self._scan_url_for_stack_traces(session, target_id, asset_id, url)
                  for asset_id, url in urls],
                return_exceptions=True,
            )
        return {"found": len(urls), "vulnerable": 0}

    async def _get_url_assets(self, target_id: int, scope_manager: ScopeManager):
        """Get all URL assets for the target, seeding base URL if none exist."""
        from lib_webbh import get_session
        from lib_webbh.database import Asset, Target
        from sqlalchemy import select

        async with get_session() as session:
            rows = (await session.execute(
                select(Asset.id, Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                )
            )).all()

        if not rows:
            async with get_session() as session:
                target = await session.get(Target, target_id)
            if target and target.base_domain:
                base_url = f"http://{target.base_domain}"
                asset_id = await self.save_asset(target_id, "url", base_url)
                rows = [(asset_id, base_url)]

        return [
            (asset_id, url)
            for asset_id, url in rows
            if scope_manager.is_in_scope(url)
        ]

    async def _scan_url_for_stack_traces(
        self, session: aiohttp.ClientSession, target_id: int, asset_id: int, base_url: str
    ):
        """Scan a URL for stack trace disclosures using concurrent requests."""
        timeout = aiohttp.ClientTimeout(total=5)

        stack_trace_payloads = [
            "?debug=true", "?trace=1", "?error=1", "?exception=true",
            "?file=php://filter/convert.base64-encode/resource=index.php",
            "?page=../../../../var/log/apache2/error.log",
            "?show_errors=1", "?display_errors=1", "?phpinfo=1",
            "?ASP.NET_SessionId=debug", "?trace.axd",
            "?debug=true&verbose=1",
            "?action=show&controller=rails/info/properties",
            "?stacktrace=1", "?backtrace=true", "?dev=true",
        ]

        debug_endpoints = [
            "/debug", "/trace", "/errors", "/stacktrace", "/phpinfo.php",
            "/server-status", "/server-info", "/trace.axd", "/elmah.axd", "/rails/info",
        ]

        async def _probe_payload(payload: str) -> None:
            test_url = base_url + payload
            try:
                async with session.get(test_url, timeout=timeout) as resp:
                    body = await resp.text()
                    for trace in self.extract_stack_trace(body):
                        fw = trace.get("framework", "Unknown")
                        await self.save_vulnerability(
                            target_id=target_id, asset_id=asset_id, severity="high",
                            title=f"Stack Trace Disclosure ({fw})",
                            description=f"Stack trace in {fw} at {test_url}",
                            poc=test_url, evidence=str(trace),
                            vuln_type="information_disclosure",
                        )
                    for header_name in ["x-debug-token", "x-error-details", "x-stack-trace", "x-exception"]:
                        if header_name in resp.headers:
                            await self.save_vulnerability(
                                target_id=target_id, asset_id=asset_id, severity="medium",
                                title="Debug Information in HTTP Headers",
                                description=f"Debug info in header '{header_name}' at {test_url}",
                                poc=test_url, evidence=f"{header_name}: {resp.headers[header_name]}",
                                vuln_type="information_disclosure",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        async def _probe_endpoint(endpoint: str) -> None:
            for test_url in [base_url.rstrip("/") + endpoint, base_url + endpoint]:
                try:
                    async with session.get(test_url, timeout=timeout) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            debug_indicators = [
                                "stack trace", "traceback", "debug", "error log",
                                "phpinfo", "server status", "environment variables",
                            ]
                            if any(ind in body.lower() for ind in debug_indicators):
                                await self.save_vulnerability(
                                    target_id=target_id, asset_id=asset_id, severity="high",
                                    title="Accessible Debug Endpoint",
                                    description=f"Debug info accessible at {test_url}",
                                    poc=test_url, evidence=body[:500],
                                    vuln_type="information_disclosure",
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        await asyncio.gather(
            *[_probe_payload(p) for p in stack_trace_payloads],
            *[_probe_endpoint(e) for e in debug_endpoints],
            return_exceptions=True,
        )
