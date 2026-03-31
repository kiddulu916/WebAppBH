# workers/cryptography/tools/padding_oracle_tester.py
"""Padding oracle testing tool — detects CBC padding oracle vulnerabilities."""

import asyncio
import aiohttp
from workers.cryptography.base_tool import CryptographyTool


class PaddingOracleTester(CryptographyTool):
    """Test for padding oracle vulnerabilities in encrypted parameters."""

    async def execute(self, target_id: int, **kwargs):
        """Execute padding oracle tests against target URLs."""
        urls = await self._get_target_urls(target_id)

        for url in urls:
            await self._test_padding_oracle(target_id, url)

    async def _get_target_urls(self, target_id: int):
        """Get URLs that might contain encrypted parameters."""
        from lib_webbh import get_session, Asset
        from sqlalchemy import select

        urls = []
        async with get_session() as session:
            result = await session.execute(
                select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url"
                )
            )
            for row in result:
                urls.append(row[0])
        return urls

    async def _test_padding_oracle(self, target_id: int, base_url: str):
        """Test a single URL for padding oracle vulnerabilities."""
        # Common parameter names that might contain encrypted data
        encrypted_params = ["data", "encrypted", "token", "cipher", "enc", "payload"]

        async with aiohttp.ClientSession() as session:
            for param in encrypted_params:
                # Try to find URLs with encrypted parameters
                test_urls = [
                    f"{base_url}?{param}=test",
                    f"{base_url}?id=1&{param}=test",
                ]

                for test_url in test_urls:
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                # If we get a successful response, try padding oracle attack
                                await self._perform_padding_oracle_attack(session, target_id, test_url, param)
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

    async def _perform_padding_oracle_attack(self, session: aiohttp.ClientSession, target_id: int, base_url: str, param: str):
        """Perform a basic padding oracle attack simulation."""
        # This is a simplified demonstration - real padding oracle attacks are complex
        # In practice, this would require analyzing response patterns for different padding

        # Test with various padding lengths (simplified)
        padding_tests = [
            "A" * 16,  # Block size for AES
            "A" * 32,  # Two blocks
            "A" * 15,  # One byte short
            "A" * 17,  # One byte over
        ]

        error_responses = []
        normal_responses = []

        for padding in padding_tests:
            try:
                test_url = f"{base_url}&{param}={padding}"
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    response_text = await resp.text()

                    # Look for error patterns that might indicate padding issues
                    if resp.status >= 400 or "padding" in response_text.lower() or "decrypt" in response_text.lower():
                        error_responses.append((padding, resp.status, response_text[:100]))
                    else:
                        normal_responses.append((padding, resp.status))

            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

        # Analyze patterns - if we see different error responses for different padding,
        # it might indicate a padding oracle vulnerability
        if len(error_responses) > 0 and len(normal_responses) > 0:
            await self.save_vulnerability(
                target_id=target_id,
                severity="high",
                title="Potential Padding Oracle Vulnerability",
                description=f"Parameter '{param}' at {base_url} shows potential padding oracle behavior",
                poc=base_url,
                evidence=f"Error responses: {len(error_responses)}, Normal responses: {len(normal_responses)}",
                vuln_type="padding_oracle",
            )