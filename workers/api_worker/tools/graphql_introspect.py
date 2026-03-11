"""GraphqlIntrospectTool -- Stage 1 GraphQL introspection scanner.

Pure-Python (httpx) tool that probes common GraphQL endpoint paths,
sends a full introspection query, parses the schema, and saves
discovered queries/mutations to api_schemas.  Introspection being
enabled is also saved as a medium-severity vulnerability.
"""

from __future__ import annotations

import json

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass

logger = setup_logger("graphql-introspect")

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/graphql/v1"]

FULL_INTROSPECTION_QUERY = json.dumps({
    "query": """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args { name }
      }
    }
  }
}"""
})


class GraphqlIntrospectTool(ApiTestTool):
    """Discover GraphQL endpoints and extract schemas via introspection."""

    name = "graphql_introspect"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Introspection response parsing
    # ------------------------------------------------------------------

    def parse_introspection(self, data: dict) -> list[dict]:
        """Parse introspection response into an endpoint list.

        Returns::

            [{"path": "query:users", "method": "QUERY",
              "params": {"args": ["limit"]}}]
        """
        endpoints: list[dict] = []
        schema = data.get("data", {}).get("__schema", {})

        query_type_name = (schema.get("queryType") or {}).get("name", "Query")
        mutation_type_name = (schema.get("mutationType") or {}).get(
            "name", "Mutation"
        )

        for type_info in schema.get("types", []):
            if type_info.get("kind") != "OBJECT":
                continue

            type_name = type_info.get("name", "")
            if type_name == query_type_name:
                op = "query"
                method = "QUERY"
            elif type_name == mutation_type_name:
                op = "mutation"
                method = "MUTATION"
            else:
                continue

            for field in type_info.get("fields") or []:
                field_name = field.get("name", "")
                args = [
                    a.get("name", "") for a in (field.get("args") or [])
                ]
                endpoints.append({
                    "path": f"{op}:{field_name}",
                    "method": method,
                    "params": {"args": args} if args else None,
                })

        return endpoints

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
            log.info("Skipping graphql_introspect -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        client = httpx.AsyncClient(
            timeout=15.0,
            headers=headers or {},
            follow_redirects=True,
        )

        try:
            for asset_id, domain in urls:
                base_url = (
                    domain if domain.startswith("http") else f"https://{domain}"
                )

                for gql_path in GRAPHQL_PATHS:
                    endpoint = f"{base_url}{gql_path}"
                    try:
                        resp = await client.post(
                            endpoint,
                            content=FULL_INTROSPECTION_QUERY,
                            headers={"Content-Type": "application/json"},
                        )

                        if resp.status_code != 200:
                            continue

                        body = resp.text
                        if "__schema" not in body:
                            continue

                        try:
                            data = resp.json()
                        except (json.JSONDecodeError, ValueError):
                            continue

                        log.info(
                            f"GraphQL introspection enabled at {endpoint}"
                        )

                        # Parse schema into endpoints
                        endpoints = self.parse_introspection(data)
                        stats["found"] += len(endpoints)

                        for ep in endpoints:
                            await self._save_api_schema(
                                target_id=target_id,
                                asset_id=asset_id,
                                method=ep["method"],
                                path=ep["path"],
                                params=ep.get("params"),
                                source_tool="graphql_introspect",
                                spec_type="graphql",
                            )
                            stats["in_scope"] += 1
                            stats["new"] += 1

                        # Introspection enabled = medium severity vuln
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=(
                                f"GraphQL introspection enabled at "
                                f"{gql_path} on {domain}"
                            ),
                            description=(
                                f"The GraphQL endpoint at {endpoint} has "
                                f"introspection enabled. This exposes the "
                                f"full API schema, types, and queries to "
                                f"any requester."
                            ),
                            poc=endpoint,
                        )

                    except Exception as exc:
                        log.debug(
                            f"GraphQL introspection probe failed for "
                            f"{endpoint}: {exc}"
                        )

        finally:
            await client.aclose()

        await self.update_tool_state(target_id, container_name)
        log.info("graphql_introspect complete", extra=stats)
        return stats
