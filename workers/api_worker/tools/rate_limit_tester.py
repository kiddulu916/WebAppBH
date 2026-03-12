"""RateLimitTesterTool -- Stage 4 rate limiting verification.

Pure-httpx tool that tests sensitive API endpoints (login, reset, otp, etc.)
for missing rate limiting by firing burst requests and checking for
429 / Retry-After responses.
"""

from __future__ import annotations

import asyncio

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass

logger = setup_logger("rate-limit-tester")

SENSITIVE_PATTERNS: list[str] = [
    "login",
    "reset",
    "otp",
    "register",
    "transfer",
    "payment",
    "verify",
]


class RateLimitTesterTool(ApiTestTool):
    """Test sensitive endpoints for missing rate limiting."""

    name = "rate_limit_tester"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Endpoint classification
    # ------------------------------------------------------------------

    def is_sensitive_endpoint(self, path: str) -> bool:
        """Return True if any SENSITIVE_PATTERNS pattern appears in the path."""
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in SENSITIVE_PATTERNS)

    def should_skip_dos(self, oos_attacks: list[str]) -> bool:
        """Return True if 'No DoS' is in the out-of-scope attacks list."""
        return "No DoS" in oos_attacks

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping rate_limit_tester -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        profile = target.target_profile or {}

        # Respect out-of-scope attack restrictions
        oos_attacks = profile.get("oos_attacks", [])
        if self.should_skip_dos(oos_attacks):
            log.info("Skipping rate_limit_tester -- DoS out of scope")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        schemas = await self._get_api_schemas(target_id)
        if not schemas:
            log.info("No API schemas found for rate limit testing")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Filter to sensitive endpoints
        sensitive = [s for s in schemas if self.is_sensitive_endpoint(s.path)]
        if not sensitive:
            log.info("No sensitive endpoints found for rate limit testing")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Get base URLs
        api_urls = await self._get_api_urls(target_id)
        if not api_urls:
            api_urls = await self._get_live_urls(target_id)
        if not api_urls:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        burst_count = profile.get("rate_limit_burst", 50)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        client = httpx.AsyncClient(
            timeout=15.0,
            headers=headers or {},
            follow_redirects=True,
        )

        try:
            for schema in sensitive:
                # Determine base URL
                asset_id = schema.asset_id
                base_url = None
                for aid, url_val in api_urls:
                    if aid == asset_id:
                        base_url = url_val if url_val.startswith("http") else f"https://{url_val}"
                        break
                if base_url is None:
                    base_url = api_urls[0][1]
                    if not base_url.startswith("http"):
                        base_url = f"https://{base_url}"
                    asset_id = api_urls[0][0]

                from urllib.parse import urlparse
                parsed_base = urlparse(base_url)
                host_url = f"{parsed_base.scheme}://{parsed_base.netloc}"
                full_url = f"{host_url}{schema.path}"

                # Fire burst of requests
                got_429 = False
                got_retry_after = False

                async def _fire_request() -> tuple[int, dict]:
                    try:
                        resp = await client.request(
                            method=schema.method or "POST",
                            url=full_url,
                            json={},
                        )
                        return resp.status_code, dict(resp.headers)
                    except Exception:
                        return 0, {}

                tasks = [_fire_request() for _ in range(burst_count)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        continue
                    status, resp_headers = result
                    if status == 429:
                        got_429 = True
                    if "retry-after" in resp_headers:
                        got_retry_after = True

                # Missing rate limiting = no 429 and no Retry-After
                if not got_429 and not got_retry_after:
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="medium",
                        title=f"Missing rate limiting on {schema.method} {schema.path}",
                        description=(
                            f"Sensitive endpoint {schema.method} {schema.path} "
                            f"did not return 429 or Retry-After after {burst_count} "
                            f"rapid requests. This may allow brute-force attacks."
                        ),
                        poc=f"{burst_count}x {schema.method} {full_url}",
                    )

        finally:
            await client.aclose()

        await self.update_tool_state(target_id, container_name)
        log.info("rate_limit_tester complete", extra=stats)
        return stats
