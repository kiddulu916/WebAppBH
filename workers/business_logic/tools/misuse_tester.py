# workers/business_logic/tools/misuse_tester.py
"""Application misuse testing tool — WSTG 4.10.7."""

import asyncio
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class MisuseTester(BusinessLogicTool):
    """Test for application misuse vulnerabilities."""

    async def execute(self, target_id: int, **kwargs):
        """Execute application misuse tests."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return {"found": 0, "vulnerable": 0}

        stats = {"found": 0, "vulnerable": 0}

        urls = await self._get_application_urls(target_id, scope_manager)
        stats["found"] = len(urls)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in urls:
                vulns_before = await self._count_vulnerabilities(target_id)
                await self._test_application_misuse(session, target_id, asset_id, url)
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
                .where(Vulnerability.vuln_type == "application_misuse")
            )
            return result.scalar() or 0

    async def _get_application_urls(self, target_id: int, scope_manager):
        """Get application URLs for testing."""
        from lib_webbh import get_session, Asset
        from sqlalchemy import select

        urls = []
        async with get_session() as session:
            result = await session.execute(
                select(Asset.id, Asset.asset_value)
                .where(Asset.target_id == target_id)
                .where(Asset.asset_type == "url")
            )

            for row in result:
                asset_id, url = row
                if scope_manager.is_in_scope(url):
                    urls.append((asset_id, url))

        return urls

    async def _test_application_misuse(self, session, target_id, asset_id, url):
        """Test application misuse scenarios."""
        # Test parameter manipulation for misuse
        misuse_tests = [
            f"{url}?admin=true",
            f"{url}?debug=1",
        ]

        for test_url in misuse_tests:
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        response_text = await resp.text()
                        if "admin" in response_text.lower() or "debug" in response_text.lower():
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title="Application Misuse Vulnerability",
                                description=f"Application functionality can be misused at {test_url}",
                                poc=test_url,
                                vuln_type="application_misuse",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                continue
