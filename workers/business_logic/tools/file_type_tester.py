# workers/business_logic/tools/file_type_tester.py
"""File upload validation testing tool — WSTG 4.10.8."""

import asyncio
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class FileTypeTester(BusinessLogicTool):
    """Test for file upload validation bypasses."""

    async def execute(self, target_id: int, **kwargs):
        """Execute file upload validation tests."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return {"found": 0, "vulnerable": 0}

        stats = {"found": 0, "vulnerable": 0}

        upload_endpoints = await self._get_upload_endpoints(target_id, scope_manager)
        stats["found"] = len(upload_endpoints)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in upload_endpoints:
                vulns_before = await self._count_vulnerabilities(target_id)
                await self._test_file_upload_validation(session, target_id, asset_id, url)
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
                .where(Vulnerability.vuln_type == "file_upload_validation")
            )
            return result.scalar() or 0

    async def _get_upload_endpoints(self, target_id: int, scope_manager):
        """Get file upload endpoints."""
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
                if scope_manager.is_in_scope(url) and any(keyword in url.lower() for keyword in ['upload', 'file', 'image']):
                    endpoints.append((asset_id, url))

        return endpoints

    async def _test_file_upload_validation(self, session, target_id, asset_id, url):
        """Test file upload validation."""
        # Test with malicious file extensions
        malicious_files = [
            ("shell.php", "php"),
            ("script.js", "js"),
            ("exploit.asp", "asp"),
            ("backdoor.jsp", "jsp"),
        ]

        for filename, ext in malicious_files:
            try:
                # Create multipart form data
                data = aiohttp.FormData()
                data.add_field('file', b'malicious content', filename=filename)

                async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        response_text = await resp.text()
                        if "uploaded" in response_text.lower() or "success" in response_text.lower():
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title="File Upload Validation Bypass",
                                description=f"Dangerous file type ({ext}) accepted for upload at {url}",
                                poc=url,
                                evidence=f"File: {filename}",
                                vuln_type="file_upload_validation",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                continue
