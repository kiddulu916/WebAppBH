"""OpenapiParserTool -- Stage 1 OpenAPI / Swagger spec discovery and parsing.

Pure-Python (httpx) tool that probes common spec paths on live URLs,
parses discovered OpenAPI 3.0 / Swagger 2.0 specs, and saves endpoints
to api_schemas.  Downloaded specs are also saved to /tmp/api-specs/
for consumption by TrufflehogTool.
"""

from __future__ import annotations

import json
import os

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass

logger = setup_logger("openapi-parser")

SPECS_DIR = "/tmp/api-specs"

SPEC_PATHS = [
    "/swagger.json",
    "/openapi.yaml",
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
]


class OpenapiParserTool(ApiTestTool):
    """Discover and parse OpenAPI / Swagger specifications."""

    name = "openapi_parser"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Spec parsing
    # ------------------------------------------------------------------

    def parse_spec(self, spec_data: dict) -> list[dict]:
        """Parse OpenAPI 3.0 or Swagger 2.0 spec.

        Returns a list of endpoint dicts::

            [{"method": "GET", "path": "/api/v1/users",
              "params": {...}, "content_type": "..."}]
        """
        endpoints: list[dict] = []
        paths = spec_data.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.upper() not in (
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                ):
                    continue
                if not isinstance(details, dict):
                    continue

                endpoint: dict = {
                    "method": method.upper(),
                    "path": path,
                    "params": {},
                    "content_type": None,
                }

                # Extract query / path / header parameters
                params = details.get("parameters", [])
                query_params = [
                    p["name"] for p in params
                    if isinstance(p, dict) and p.get("in") == "query"
                ]
                path_params = [
                    p["name"] for p in params
                    if isinstance(p, dict) and p.get("in") == "path"
                ]
                header_params = [
                    p["name"] for p in params
                    if isinstance(p, dict) and p.get("in") == "header"
                ]
                if query_params:
                    endpoint["params"]["query"] = query_params
                if path_params:
                    endpoint["params"]["path"] = path_params
                if header_params:
                    endpoint["params"]["header"] = header_params

                # Extract body params from requestBody (OpenAPI 3.0)
                request_body = details.get("requestBody", {})
                if isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    for ct, schema_info in content.items():
                        endpoint["content_type"] = ct
                        if isinstance(schema_info, dict):
                            props = (
                                schema_info
                                .get("schema", {})
                                .get("properties", {})
                            )
                            if props:
                                endpoint["params"]["body"] = list(props.keys())
                        break

                if not endpoint["params"]:
                    endpoint["params"] = None
                endpoints.append(endpoint)

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
            log.info("Skipping openapi_parser -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        os.makedirs(SPECS_DIR, exist_ok=True)

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

                for spec_path in SPEC_PATHS:
                    endpoint = f"{base_url}{spec_path}"
                    try:
                        resp = await client.get(endpoint)
                        if resp.status_code != 200:
                            continue

                        # Try to parse as JSON
                        try:
                            spec_data = resp.json()
                        except (json.JSONDecodeError, ValueError):
                            continue

                        # Quick sanity check — must have "paths" key
                        if "paths" not in spec_data:
                            continue

                        log.info(f"Found OpenAPI spec at {endpoint}")

                        # Save raw spec to disk for TrufflehogTool
                        safe_name = (
                            domain.replace("/", "_")
                            .replace(":", "_")
                            + spec_path.replace("/", "_")
                            + ".json"
                        )
                        spec_file = os.path.join(SPECS_DIR, safe_name)
                        with open(spec_file, "w") as fh:
                            json.dump(spec_data, fh)

                        # Parse endpoints
                        endpoints = self.parse_spec(spec_data)
                        stats["found"] += len(endpoints)

                        for ep in endpoints:
                            await self._save_api_schema(
                                target_id=target_id,
                                asset_id=asset_id,
                                method=ep["method"],
                                path=ep["path"],
                                params=ep.get("params"),
                                content_type=ep.get("content_type"),
                                source_tool="openapi_parser",
                                spec_type="openapi",
                            )
                            stats["in_scope"] += 1
                            stats["new"] += 1

                    except Exception as exc:
                        log.debug(f"OpenAPI probe failed for {endpoint}: {exc}")

        finally:
            await client.aclose()

        await self.update_tool_state(target_id, container_name)
        log.info("openapi_parser complete", extra=stats)
        return stats
