# workers/business_logic/tools/request_forgery_tester.py
"""Request forgery testing tool — WSTG 4.10.2."""

import asyncio
import aiohttp
from workers.business_logic.base_tool import BusinessLogicTool


class RequestForgeryTester(BusinessLogicTool):
    """Test for request forgery vulnerabilities using proxy."""

    async def execute(self, target_id: int, **kwargs):
        """Execute request forgery tests using traffic proxy."""
        scope_manager = kwargs.get("scope_manager")
        if not scope_manager:
            return

        # Get forms and POST endpoints that might be vulnerable to request forgery
        forms_and_endpoints = await self._get_forms_and_endpoints(target_id, scope_manager)

        async with aiohttp.ClientSession() as session:
            for asset_id, url, method, params in forms_and_endpoints:
                await self._test_request_forgery(session, target_id, asset_id, url, method, params)

    async def _get_forms_and_endpoints(self, target_id: int, scope_manager):
        """Get forms and POST endpoints for testing."""
        from lib_webbh import get_session, Asset, Parameter
        from sqlalchemy import select

        forms_and_endpoints = []
        async with get_session() as session:
            # Get URLs with POST parameters (potential form endpoints)
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
                # Assume POST for URLs with form-like parameters
                forms_and_endpoints.append((params[0][0], url, "POST", params))

        return forms_and_endpoints

    async def _test_request_forgery(self, session: aiohttp.ClientSession, target_id: int, asset_id: int, url: str, method: str, params):
        """Test for request forgery vulnerabilities."""

        # Test 1: Parameter pollution - duplicate parameters
        await self._test_parameter_pollution(session, target_id, asset_id, url, params)

        # Test 2: Referer header manipulation
        await self._test_referer_manipulation(session, target_id, asset_id, url, params)

        # Test 3: Origin header manipulation
        await self._test_origin_manipulation(session, target_id, asset_id, url, params)

        # Test 4: Request replay attacks
        await self._test_request_replay(session, target_id, asset_id, url, params)

    async def _test_parameter_pollution(self, session, target_id, asset_id, url, params):
        """Test parameter pollution attacks."""
        if not params:
            return

        # Create URL with duplicate parameters
        param_str = "&".join([f"{param_name}=test1&{param_name}=test2" for _, param_name, _ in params[:2]])
        test_url = f"{url}?{param_str}"

        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    response_text = await resp.text()
                    # If both parameter values were processed, it might be vulnerable
                    if "test1" in response_text and "test2" in response_text:
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title="Parameter Pollution Vulnerability",
                            description=f"URL accepts duplicate parameters which may allow request forgery at {test_url}",
                            poc=test_url,
                            vuln_type="request_forgery",
                        )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    async def _test_referer_manipulation(self, session, target_id, asset_id, url, params):
        """Test referer header manipulation."""
        headers = {
            "Referer": "https://evil-attacker.com/malicious-site",
        }

        # Try POST request with malicious referer
        data = {param_name: "test" for _, param_name, _ in params[:3]}  # Use first 3 params

        try:
            async with session.post(url, headers=headers, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    response_text = await resp.text()
                    # If request was accepted despite malicious referer, flag potential CSRF
                    if "success" in response_text.lower() or len(response_text) > 100:
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title="Weak Referer Validation",
                            description=f"Request accepted with malicious referer header at {url}",
                            poc=url,
                            evidence=f"Referer: {headers['Referer']}",
                            vuln_type="request_forgery",
                        )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    async def _test_origin_manipulation(self, session, target_id, asset_id, url, params):
        """Test origin header manipulation."""
        headers = {
            "Origin": "https://evil-attacker.com",
        }

        data = {param_name: "test" for _, param_name, _ in params[:3]}

        try:
            async with session.post(url, headers=headers, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    response_text = await resp.text()
                    if "success" in response_text.lower() or len(response_text) > 100:
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title="Weak Origin Validation",
                            description=f"Request accepted with malicious origin header at {url}",
                            poc=url,
                            evidence=f"Origin: {headers['Origin']}",
                            vuln_type="request_forgery",
                        )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    async def _test_request_replay(self, session, target_id, asset_id, url, params):
        """Test for request replay vulnerabilities."""
        # Capture a baseline request
        data = {param_name: f"value_{i}" for i, (_, param_name, _) in enumerate(params[:3])}

        try:
            # Make initial request
            async with session.post(url, data=data.copy(), timeout=aiohttp.ClientTimeout(total=10)) as resp:
                initial_response = await resp.text()
                initial_status = resp.status

            # Replay the same request immediately
            await asyncio.sleep(0.1)  # Small delay

            async with session.post(url, data=data.copy(), timeout=aiohttp.ClientTimeout(total=10)) as resp:
                replay_response = await resp.text()
                replay_status = resp.status

                # If replay succeeded when it shouldn't (e.g., one-time tokens), flag it
                if initial_status == 200 and replay_status == 200:
                    # Check if responses are identical (might indicate lack of CSRF protection)
                    if initial_response == replay_response:
                        await self.save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="low",
                            title="Potential Request Replay Vulnerability",
                            description=f"Identical requests produce identical responses at {url}, may lack anti-replay protection",
                            poc=url,
                            vuln_type="request_forgery",
                        )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass