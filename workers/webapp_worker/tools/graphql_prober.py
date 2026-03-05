"""GraphqlProber — Stage 5 GraphQL endpoint discovery and introspection check.

Probes common GraphQL endpoint paths and tests whether introspection
is enabled, which exposes the full API schema to attackers.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("graphql-prober")

# Common GraphQL endpoint paths.
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/gql", "/query"]

# Minimal introspection query to test if introspection is enabled.
INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'


class GraphqlProber(WebAppTool):
    """Discover GraphQL endpoints and check for introspection."""

    name = "graphql_prober"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Probe GraphQL endpoints on live URLs.

        Returns a stats dict with keys: urls_checked, endpoints_found,
        introspection_enabled, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="graphql")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping graphql_prober — within cooldown period")
            return {
                "urls_checked": 0,
                "endpoints_found": 0,
                "introspection_enabled": 0,
                "skipped_cooldown": True,
            }

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {
                "urls_checked": 0,
                "endpoints_found": 0,
                "introspection_enabled": 0,
                "skipped_cooldown": False,
            }

        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=True,
            )
            should_close = True

        urls_checked = 0
        endpoints_found = 0
        introspection_count = 0

        try:
            for asset_id, domain in urls:
                base_url = f"https://{domain}"
                urls_checked += 1

                for gql_path in GRAPHQL_PATHS:
                    endpoint = f"{base_url}{gql_path}"
                    try:
                        resp = await client.post(
                            endpoint,
                            content=INTROSPECTION_QUERY,
                            headers={"Content-Type": "application/json"},
                        )

                        if resp.status_code != 200:
                            continue

                        body = resp.text
                        endpoints_found += 1

                        # Save observation
                        await self._save_observation(
                            asset_id=asset_id,
                            status_code=resp.status_code,
                            page_title=None,
                            tech_stack={"graphql_endpoint": endpoint},
                            headers=dict(resp.headers),
                        )

                        # Check for introspection
                        if "__schema" in body:
                            introspection_count += 1
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title=f"GraphQL introspection enabled at {gql_path} on {domain}",
                                description=(
                                    f"The GraphQL endpoint at {endpoint} has "
                                    f"introspection enabled. This exposes the "
                                    f"full API schema, types, and queries to "
                                    f"any requester."
                                ),
                                poc=endpoint,
                            )

                    except Exception as exc:
                        log.debug(f"GraphQL probe failed for {endpoint}: {exc}")

        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "endpoints_found": endpoints_found,
            "introspection_enabled": introspection_count,
            "skipped_cooldown": False,
        }
        log.info("graphql_prober complete", extra=stats)
        return stats
