# workers/business_logic/tools/rate_limit_tester.py
"""Rate limiting testing tool — WSTG 4.10.5."""

import asyncio
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class RateLimitTester(BusinessLogicTool):
    """Test for rate limiting bypasses."""

    async def execute(self, target_id: int, **kwargs):
        """Execute rate limiting tests against target."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return {"found": 0, "vulnerable": 0}

        stats = {"found": 0, "vulnerable": 0}

        # Get endpoints that might have rate limiting
        endpoints = await self._get_rate_limited_endpoints(target_id, scope_manager)
        stats["found"] = len(endpoints)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in endpoints:
                vulns_before = await self._count_vulnerabilities(target_id)
                await self._test_rate_limiting(session, target_id, asset_id, url)
                vulns_after = await self._count_vulnerabilities(target_id)
                stats["vulnerable"] += vulns_after - vulns_before

        return stats

    async def _count_vulnerabilities(self, target_id: int) -> int:
        """Count existing vulnerabilities for this target."""
        from lib_webbh import get_session, Vulnerability
        from sqlalchemy import select, func

        async with get_session() as session:
            result = await session.execute(
                select(func.count(Vulnerability.id))
                .where(Vulnerability.target_id == target_id)
                .where(Vulnerability.vuln_type == "rate_limiting_bypass")
            )
            return result.scalar() or 0

    async def _get_rate_limited_endpoints(self, target_id: int, scope_manager):
        """Get endpoints that typically have rate limiting."""
        from lib_webbh import get_session, Asset
        from sqlalchemy import select

        endpoints = []
        async with get_session() as session:
            result = await session.execute(
                select(Asset.id, Asset.asset_value)
                .where(Asset.target_id == target_id)
                .where(Asset.asset_type == "url")
            )

            for row in result:
                asset_id, url = row
                if scope_manager.is_in_scope(url):
                    # Check for common rate-limited endpoints
                    if any(keyword in url.lower() for keyword in ['login', 'auth', 'password', 'reset', 'otp', '2fa', 'api']):
                        endpoints.append((asset_id, url))

        return endpoints

    async def _test_rate_limiting(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, url: str):
        """Test rate limiting on an endpoint."""

        # Test 1: Basic rate limiting bypass
        await self._test_basic_rate_limit(session, target_id, asset_id, url)

    async def _test_basic_rate_limit(self, session, target_id, asset_id, url):
        """Test basic rate limiting with rapid requests."""
        # Send multiple rapid requests
        request_count = 10
        success_count = 0
        rate_limited_count = 0

        for i in range(request_count):
            try:
                data = {"username": f"user{i}", "password": "password123"}
                async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        success_count += 1
                    elif resp.status in [429, 503]:  # Common rate limit status codes
                        rate_limited_count += 1
                    await resp.text()  # Consume response
                await asyncio.sleep(0.1)  # Small delay between requests
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                continue

        # If rate limiting is not detected, flag potential vulnerability
        if request_count >= 5 and rate_limited_count == 0:
            await self.save_vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity="medium",
                title="Missing Rate Limiting",
                description=f"No rate limiting detected after {request_count} rapid requests to {url}",
                poc=url,
                evidence=f"Successful requests: {success_count}/{request_count}",
                vuln_type="rate_limiting_bypass",
            )
