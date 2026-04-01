# workers/business_logic/tools/business_validation_tester.py
"""Business data validation testing tool — WSTG 4.10.1."""

import asyncio
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class BusinessValidationTester(BusinessLogicTool):
    """Test for business data validation vulnerabilities."""

    async def execute(self, target_id: int, **kwargs):
        """Execute business validation tests against target URLs."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        # Get all URL assets and parameters
        urls_and_params = await self._get_urls_with_parameters(target_id, scope_manager)

        async with aiohttp.ClientSession() as session:
            for asset_id, url, params in urls_and_params:
                await self._test_business_validation(session, target_id, asset_id, url, params)

    async def _get_urls_with_parameters(self, target_id: int, scope_manager):
        """Get URLs that have parameters for testing."""
        from lib_webbh import get_session, Asset, Parameter
        from sqlalchemy import select

        urls_and_params = []
        async with get_session() as session:
            # Get URLs with their parameters
            result = await session.execute(
                select(Asset.id, Asset.asset_value, Parameter.param_name, Parameter.param_type)
                .join(Parameter, Asset.id == Parameter.asset_id)
                .where(Asset.target_id == target_id)
                .where(Asset.asset_type == "url")
            )

            url_params = {}
            for row in result:
                asset_id, url, param_name, param_type = row
                if scope_manager.is_in_scope(url):
                    if url not in url_params:
                        url_params[url] = []
                    url_params[url].append((asset_id, param_name, param_type))

            for url, params in url_params.items():
                urls_and_params.append((params[0][0], url, params))

        return urls_and_params

    async def _test_business_validation(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, base_url: str, params):
        """Test business validation on a URL with parameters."""

        # Test cases for business logic validation
        test_cases = [
            # Parameter tampering - negative values where positive expected
            self._test_negative_values,
            # Boundary testing - extreme values
            self._test_boundary_values,
            # Type confusion - strings where numbers expected
            self._test_type_confusion,
            # Length validation - overly long inputs
            self._test_length_validation,
            # Format validation - invalid formats
            self._test_format_validation,
        ]

        for test_case in test_cases:
            try:
                await test_case(session, target_id, asset_id, base_url, params)
            except Exception:
                continue  # Skip individual test failures

    async def _test_negative_values(self, session, target_id, asset_id, base_url, params):
        """Test negative values in parameters that should be positive."""
        for param_asset_id, param_name, param_type in params:
            if param_type in ['integer', 'float', 'number']:
                test_url = f"{base_url}?{param_name}=-1"
                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            response_text = await resp.text()
                            # Check if negative value was accepted when it shouldn't be
                            if "quantity" in param_name.lower() or "amount" in param_name.lower() or "price" in param_name.lower():
                                await self.save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="medium",
                                    title="Negative Value Accepted in Business Parameter",
                                    description=f"Parameter '{param_name}' accepted negative value -1 at {test_url}",
                                    poc=test_url,
                                    vuln_type="business_logic_validation",
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

    async def _test_boundary_values(self, session, target_id, asset_id, base_url, params):
        """Test extreme boundary values."""
        boundary_values = [0, 1, -1, 999999, -999999, 2147483647, -2147483648]  # int limits

        for param_asset_id, param_name, param_type in params:
            if param_type in ['integer', 'float', 'number']:
                for value in boundary_values:
                    test_url = f"{base_url}?{param_name}={value}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                # Check for potential issues with boundary values
                                response_text = await resp.text()
                                if "error" in response_text.lower() and ("overflow" in response_text.lower() or "invalid" in response_text.lower()):
                                    await self.save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity="low",
                                        title="Boundary Value Handling Issue",
                                        description=f"Parameter '{param_name}' with boundary value {value} caused error at {test_url}",
                                        poc=test_url,
                                        evidence=response_text[:200],
                                        vuln_type="business_logic_validation",
                                    )
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass

    async def _test_type_confusion(self, session, target_id, asset_id, base_url, params):
        """Test type confusion - sending wrong data types."""
        for param_asset_id, param_name, param_type in params:
            if param_type in ['integer', 'float', 'number']:
                # Send string where number expected
                test_values = ["abc", "true", "null", "<script>", "../../../etc/passwd"]

                for value in test_values:
                    test_url = f"{base_url}?{param_name}={value}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                response_text = await resp.text()
                                # If string was accepted where number expected, flag it
                                if len(response_text) > 100:  # Assume successful processing
                                    await self.save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity="low",
                                        title="Type Confusion in Parameter Validation",
                                        description=f"Parameter '{param_name}' accepted string '{value}' where number expected at {test_url}",
                                        poc=test_url,
                                        vuln_type="business_logic_validation",
                                    )
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass

    async def _test_length_validation(self, session, target_id, asset_id, base_url, params):
        """Test length validation with overly long inputs."""
        for param_asset_id, param_name, param_type in params:
            # Test extremely long input
            long_value = "A" * 10000
            test_url = f"{base_url}?{param_name}={long_value}"
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    response_text = await resp.text()
                    if resp.status == 200 and len(response_text) > 1000:  # Processed long input
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="low",
                            title="Excessive Input Length Accepted",
                            description=f"Parameter '{param_name}' accepted extremely long input (10000 chars) at {test_url}",
                            poc=test_url,
                            vuln_type="business_logic_validation",
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    async def _test_format_validation(self, session, target_id, asset_id, base_url, params):
        """Test format validation with invalid formats."""
        for param_asset_id, param_name, param_type in params:
            if 'email' in param_name.lower():
                invalid_emails = ["notanemail", "@domain.com", "user@", "user@.com", "user..user@domain.com"]
                for email in invalid_emails:
                    test_url = f"{base_url}?{param_name}={email}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                response_text = await resp.text()
                                if "success" in response_text.lower() or "processed" in response_text.lower():
                                    await self.save_vulnerability(
                                        target_id=target_id,
                                        asset_id=asset_id,
                                        severity="medium",
                                        title="Invalid Email Format Accepted",
                                        description=f"Email parameter '{param_name}' accepted invalid format '{email}' at {test_url}",
                                        poc=test_url,
                                        vuln_type="business_logic_validation",
                                    )
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass