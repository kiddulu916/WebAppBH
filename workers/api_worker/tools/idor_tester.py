"""IdorTesterTool -- Stage 3 IDOR (Insecure Direct Object Reference) testing.

Pure-httpx tool that tests API endpoints with path parameters for
horizontal and vertical privilege escalation by substituting test IDs
and comparing response bodies.
"""

from __future__ import annotations

import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import PATH_PARAM_RE, ApiTestTool
from workers.api_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("idor-tester")


class IdorTesterTool(ApiTestTool):
    """Test API endpoints for IDOR vulnerabilities."""

    name = "idor_tester"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Path parameter detection
    # ------------------------------------------------------------------

    def has_path_params(self, path: str) -> bool:
        """Return True if path matches ``/:param`` or ``/{param}`` patterns."""
        return bool(PATH_PARAM_RE.search(path))

    # ------------------------------------------------------------------
    # Test ID generation
    # ------------------------------------------------------------------

    def generate_test_ids(self) -> list[int]:
        """Generate a list of test IDs for IDOR probing."""
        return [1, 2, 3, 5, 10, 100, 0, -1]

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
            log.info("Skipping idor_tester -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        schemas = await self._get_api_schemas(target_id)
        if not schemas:
            log.info("No API schemas found for IDOR testing")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Filter endpoints with path parameters
        param_endpoints = [s for s in schemas if self.has_path_params(s.path)]
        if not param_endpoints:
            log.info("No endpoints with path parameters found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        sem = get_semaphore(self.weight_class)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Get live URLs for base URL construction
        api_urls = await self._get_api_urls(target_id)
        if not api_urls:
            api_urls = await self._get_live_urls(target_id)
        if not api_urls:
            return stats

        test_ids = self.generate_test_ids()

        client = httpx.AsyncClient(
            timeout=15.0,
            headers=headers or {},
            follow_redirects=True,
        )

        try:
            for schema in param_endpoints:
                # Determine base URL from the schema's asset or first live URL
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

                # Strip path from base_url to get just the host
                from urllib.parse import urlparse
                parsed_base = urlparse(base_url)
                host_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

                # Collect responses for different IDs to detect IDOR
                responses: dict[int, tuple[int, str]] = {}

                for test_id in test_ids:
                    # Substitute path params with test ID
                    concrete_path = PATH_PARAM_RE.sub(
                        f"/{test_id}", schema.path
                    )
                    full_url = f"{host_url}{concrete_path}"

                    await sem.acquire()
                    try:
                        try:
                            resp = await client.request(
                                method=schema.method or "GET",
                                url=full_url,
                            )
                            responses[test_id] = (resp.status_code, resp.text)
                        except Exception as exc:
                            log.debug(
                                f"IDOR request failed for {full_url}: {exc}"
                            )
                    finally:
                        sem.release()

                # Analyse responses: if different IDs return different data
                # with 200 status, it's a potential IDOR
                success_responses = {
                    tid: (status, body)
                    for tid, (status, body) in responses.items()
                    if status == 200 and body
                }

                if len(success_responses) >= 2:
                    bodies = list(success_responses.values())
                    # Check if responses contain different data
                    unique_bodies = set(b[1] for b in bodies)
                    if len(unique_bodies) > 1:
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1

                        # Determine severity
                        severity = "high"  # horizontal IDOR by default

                        # Check for privilege escalation indicators
                        for _, body in success_responses.values():
                            body_lower = body.lower()
                            if any(
                                kw in body_lower
                                for kw in ["admin", "role", "privilege", "permission"]
                            ):
                                severity = "critical"
                                break

                        tested_ids = list(success_responses.keys())
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity=severity,
                            title=f"IDOR on {schema.method} {schema.path}",
                            description=(
                                f"Endpoint {schema.method} {schema.path} returns "
                                f"different data for IDs {tested_ids}, indicating "
                                f"{'vertical privilege escalation' if severity == 'critical' else 'horizontal IDOR'}."
                            ),
                            poc=f"{schema.method} {host_url}{schema.path} with IDs {tested_ids}",
                        )

        finally:
            await client.aclose()

        await self.update_tool_state(target_id, container_name)
        log.info("idor_tester complete", extra=stats)
        return stats
