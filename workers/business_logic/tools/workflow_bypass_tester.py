# workers/business_logic/tools/workflow_bypass_tester.py
"""Workflow bypass testing tool — WSTG 4.10.6."""

import asyncio
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class WorkflowBypassTester(BusinessLogicTool):
    """Test for workflow bypass vulnerabilities."""

    async def execute(self, target_id: int, **kwargs):
        """Execute workflow bypass tests."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return {"found": 0, "vulnerable": 0}

        stats = {"found": 0, "vulnerable": 0}

        urls = await self._get_workflow_urls(target_id, scope_manager)
        stats["found"] = len(urls)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in urls:
                vulns_before = await self._count_vulnerabilities(target_id)
                await self._test_workflow_bypass(session, target_id, asset_id, url)
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
                .where(Vulnerability.vuln_type == "workflow_bypass")
            )
            return result.scalar() or 0

    async def _get_workflow_urls(self, target_id: int, scope_manager):
        """Get URLs that might involve workflows."""
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

    async def _test_workflow_bypass(self, session, target_id, asset_id, url):
        """Test workflow bypass scenarios."""
        # Test direct access to workflow steps
        workflow_steps = [
            f"{url}?step=2",
            f"{url}?step=final",
            f"{url}?action=complete",
        ]

        for step_url in workflow_steps:
            try:
                async with session.get(step_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        response_text = await resp.text()
                        if "success" in response_text.lower() or "completed" in response_text.lower():
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title="Workflow Step Bypass",
                                description=f"Workflow step directly accessible without proper validation at {step_url}",
                                poc=step_url,
                                vuln_type="workflow_bypass",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                continue
