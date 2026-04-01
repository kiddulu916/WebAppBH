# workers/business_logic/tools/integrity_tester.py
"""Integrity checks testing tool — WSTG 4.10.3."""

import asyncio
import aiohttp
import hashlib
from workers.business_logic.base_tool import BusinessLogicTool


class IntegrityTester(BusinessLogicTool):
    """Test for integrity check bypasses using proxy."""

    async def execute(self, target_id: int, **kwargs):
        """Execute integrity testing using traffic proxy."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        # Get URLs that might use integrity checks
        urls = await self._get_urls_for_integrity_testing(target_id, scope_manager)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in urls:
                await self._test_integrity_checks(session, target_id, asset_id, url)

    async def _get_urls_for_integrity_testing(self, target_id: int, scope_manager):
        """Get URLs that might involve integrity checks."""
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

    async def _test_integrity_checks(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, url: str):
        """Test various integrity check bypass scenarios."""

        # Test 1: Checksum/tampering detection
        await self._test_checksum_bypass(session, target_id, asset_id, url)

        # Test 2: Token manipulation
        await self._test_token_manipulation(session, target_id, asset_id, url)

        # Test 3: HMAC bypass attempts
        await self._test_hmac_bypass(session, target_id, asset_id, url)

        # Test 4: State manipulation
        await self._test_state_manipulation(session, target_id, asset_id, url)

    async def _test_checksum_bypass(self, session, target_id, asset_id, url):
        """Test checksum/tampering detection bypass."""
        # Try common checksum parameter names
        checksum_params = ["checksum", "hash", "md5", "sha1", "sha256", "crc", "signature"]

        for param in checksum_params:
            # Test with invalid checksum
            test_url = f"{url}?data=test&{param}=invalid_checksum"
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        response_text = await resp.text()
                        # If invalid checksum was accepted, it might be vulnerable
                        if "success" in response_text.lower() or "processed" in response_text.lower():
                            await self.save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title="Checksum Validation Bypass",
                                description=f"Invalid checksum accepted for parameter '{param}' at {test_url}",
                                poc=test_url,
                                vuln_type="integrity_bypass",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    async def _test_token_manipulation(self, session, target_id, asset_id, url):
        """Test token manipulation vulnerabilities."""
        token_params = ["token", "auth_token", "csrf_token", "session_token", "api_token"]

        for param in token_params:
            # Test with obviously invalid tokens
            invalid_tokens = ["", "null", "undefined", "invalid", "tampered_token_123"]

            for token in invalid_tokens:
                test_url = f"{url}?{param}={token}"
                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            response_text = await resp.text()
                            # If invalid token was accepted for authenticated operation
                            if "success" in response_text.lower() or "authorized" in response_text.lower():
                                await self.save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="Token Validation Bypass",
                                    description=f"Invalid token '{token}' accepted for parameter '{param}' at {test_url}",
                                    poc=test_url,
                                    vuln_type="integrity_bypass",
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

    async def _test_hmac_bypass(self, session, target_id, asset_id, url):
        """Test HMAC signature bypass."""
        # Look for HMAC-style parameters
        hmac_params = ["signature", "hmac", "sig", "digest"]

        for param in hmac_params:
            # Test with tampered data but same signature
            test_cases = [
                f"{url}?data=tampered_data&{param}=original_signature",
                f"{url}?message=modified&{param}=same_sig",
            ]

            for test_url in test_cases:
                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            response_text = await resp.text()
                            if "valid" in response_text.lower() or "accepted" in response_text.lower():
                                await self.save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="HMAC/Signature Validation Bypass",
                                    description=f"Tampered data accepted with invalid signature for parameter '{param}' at {test_url}",
                                    poc=test_url,
                                    vuln_type="integrity_bypass",
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

    async def _test_state_manipulation(self, session, target_id, asset_id, url):
        """Test state manipulation vulnerabilities."""
        state_params = ["state", "status", "step", "phase", "stage"]

        for param in state_params:
            # Try to skip states or manipulate workflow
            invalid_states = ["-1", "999", "completed", "bypassed", "admin", "root"]

            for state in invalid_states:
                test_url = f"{url}?{param}={state}"
                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            response_text = await resp.text()
                            # If invalid state was accepted
                            if "success" in response_text.lower() or len(response_text) > 200:
                                await self.save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="medium",
                                    title="State Validation Bypass",
                                    description=f"Invalid state '{state}' accepted for parameter '{param}' at {test_url}",
                                    poc=test_url,
                                    vuln_type="integrity_bypass",
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass
