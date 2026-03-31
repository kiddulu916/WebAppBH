# workers/cryptography/tools/plaintext_leak_scanner.py
"""Plaintext transmission scanner — detects unencrypted sensitive data."""

import aiohttp
from workers.cryptography.base_tool import CryptographyTool


class PlaintextLeakScanner(CryptographyTool):
    """Scan for plaintext transmission of sensitive data."""

    async def execute(self, target_id: int, **kwargs):
        """Execute plaintext leak scanning against target URLs."""
        urls = await self._get_target_urls(target_id)

        async with aiohttp.ClientSession() as session:
            for url in urls:
                await self._scan_url_for_plaintext_leaks(session, target_id, url)

    async def _get_target_urls(self, target_id: int):
        """Get URLs for the target."""
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

    async def _scan_url_for_plaintext_leaks(self, session: aiohttp.ClientSession, target_id: int, url: str):
        """Scan a URL for plaintext transmission of sensitive data."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                response_text = await resp.text()

                # Check for sensitive data patterns in HTTP responses
                sensitive_patterns = [
                    r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',  # Credit card numbers
                    r'\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b',  # SSN
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
                    r'\bpassword[\s]*[=][\s]*["\'][^"\']+["\']',  # Password fields
                    r'\bapi[_-]?key[\s]*[=][\s]*["\'][^"\']+["\']',  # API keys
                    r'\btoken[\s]*[=][\s]*["\'][^"\']+["\']',  # Tokens
                    r'\bsecret[\s]*[=][\s]*["\'][^"\']+["\']',  # Secrets
                ]

                import re
                found_leaks = []

                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, response_text, re.IGNORECASE)
                    if matches:
                        found_leaks.extend(matches[:3])  # Limit to first 3 matches per pattern

                if found_leaks:
                    await self.save_vulnerability(
                        target_id=target_id,
                        severity="high",
                        title="Plaintext Sensitive Data Transmission",
                        description=f"URL {url} transmits sensitive data in plaintext",
                        poc=url,
                        evidence=f"Found patterns: {', '.join(found_leaks[:5])}",
                        vuln_type="plaintext_transmission",
                    )

                # Also check if HTTP (not HTTPS) is being used
                if url.startswith("http://") and not url.startswith("https://"):
                    await self.save_vulnerability(
                        target_id=target_id,
                        severity="medium",
                        title="HTTP Plaintext Transmission",
                        description=f"URL {url} uses HTTP instead of HTTPS",
                        poc=url,
                        vuln_type="plaintext_transmission",
                    )

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass