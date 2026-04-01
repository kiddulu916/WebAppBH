# workers/business_logic/tools/timing_analyzer.py
"""Process timing analysis tool — WSTG 4.10.4."""

import asyncio
import time
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class TimingAnalyzer(BusinessLogicTool):
    """Analyze process timing for vulnerabilities."""

    async def execute(self, target_id: int, **kwargs):
        """Execute timing analysis against target."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        # Get URLs for timing analysis
        urls = await self._get_urls_for_timing_analysis(target_id, scope_manager)

        async with aiohttp.ClientSession() as session:
            for asset_id, url in urls:
                await self._analyze_timing(session, target_id, asset_id, url)

    async def _get_urls_for_timing_analysis(self, target_id: int, scope_manager):
        """Get URLs that might be susceptible to timing attacks."""
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

    async def _analyze_timing(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, url: str):
        """Analyze timing characteristics of the URL."""

        # Test 1: Username enumeration via timing
        await self._test_username_enumeration_timing(session, target_id, asset_id, url)

        # Test 2: Password checking timing
        await self._test_password_timing(session, target_id, asset_id, url)

    async def _test_username_enumeration_timing(self, session, target_id, asset_id, url):
        """Test for username enumeration via timing differences."""
        # Common login endpoints
        login_urls = [f"{url}/login", f"{url}?action=login", f"{url}login.php"]

        test_usernames = ["admin", "administrator", "root", "user", "test", "guest", "nonexistent_user_12345"]

        for login_url in login_urls:
            try:
                # Test with valid username format but invalid password
                timings = {}
                for username in test_usernames[:3]:  # Limit to avoid too many requests
                    start_time = time.time()
                    data = {"username": username, "password": "wrongpass123"}
                    async with session.post(login_url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        await resp.text()  # Consume response
                    end_time = time.time()
                    timings[username] = end_time - start_time

                # Analyze timing differences
                if len(timings) > 1:
                    avg_timing = sum(timings.values()) / len(timings)
                    max_timing = max(timings.values())
                    min_timing = min(timings.values())

                    # If timing difference is significant (>20%), flag potential username enumeration
                    if max_timing > min_timing * 1.2:
                        slow_usernames = [u for u, t in timings.items() if t > avg_timing * 1.1]
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title="Potential Username Enumeration via Timing",
                            description=f"Timing differences detected at {login_url} for usernames: {', '.join(slow_usernames)}",
                            poc=login_url,
                            evidence=f"Timing variance: {max_timing - min_timing:.3f}s",
                            vuln_type="timing_attack",
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

    async def _test_password_timing(self, session, target_id, asset_id, url):
        """Test for password checking timing leaks."""
        login_endpoints = [f"{url}/login", f"{url}?action=login"]

        for endpoint in login_endpoints:
            try:
                # Test different password lengths to detect timing leaks in password checking
                passwords = ["a", "aa", "aaa", "aaaa", "short", "medium_pass"]

                timings = {}
                for password in passwords:
                    start_time = time.time()
                    data = {"username": "testuser", "password": password}
                    async with session.post(endpoint, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        await resp.text()
                    end_time = time.time()
                    timings[len(password)] = end_time - start_time

                # Look for correlation between password length and response time
                if len(timings) > 3:
                    lengths = list(timings.keys())
                    times = list(timings.values())

                    # Simple correlation check
                    correlation = self._calculate_correlation(lengths, times)
                    if correlation > 0.7:  # Strong positive correlation
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="low",
                            title="Password Length Timing Leak",
                            description=f"Password checking timing correlates with length at {endpoint} (correlation: {correlation:.2f})",
                            poc=endpoint,
                            vuln_type="timing_attack",
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

    def _calculate_correlation(self, x_values, y_values):
        """Calculate Pearson correlation coefficient."""
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0

        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)
        sum_y2 = sum(y * y for y in y_values)

        numerator = n * sum_xy - sum_x * sum_y
        denominator = ((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2)) ** 0.5

        return numerator / denominator if denominator != 0 else 0
