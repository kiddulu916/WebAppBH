"""OpenApiDetector — Stage 5 OpenAPI/Swagger spec discovery.

Probes common OpenAPI specification paths to discover exposed API
documentation endpoints.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("openapi-detector")

# Common OpenAPI/Swagger paths.
OPENAPI_PATHS = [
    "/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/docs",
]


class OpenApiDetector(WebAppTool):
    """Discover exposed OpenAPI/Swagger specification endpoints."""

    name = "openapi_detector"
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
        """Probe OpenAPI paths on live URLs.

        Returns a stats dict with keys: urls_checked, specs_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="openapi")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping openapi_detector — within cooldown period")
            return {"urls_checked": 0, "specs_found": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "specs_found": 0, "skipped_cooldown": False}

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
        specs_found = 0

        try:
            for asset_id, domain in urls:
                base_url = f"https://{domain}"
                urls_checked += 1

                for api_path in OPENAPI_PATHS:
                    endpoint = f"{base_url}{api_path}"
                    try:
                        resp = await client.get(endpoint)
                        if resp.status_code != 200:
                            continue

                        body = resp.text.lower()
                        if "swagger" in body or "openapi" in body:
                            specs_found += 1

                            await self._save_asset(
                                target_id=target_id,
                                url=endpoint,
                                scope_manager=scope_manager,
                                source_tool=self.name,
                            )

                            await self._save_observation(
                                asset_id=asset_id,
                                status_code=resp.status_code,
                                page_title=None,
                                tech_stack={"openapi_spec": endpoint},
                                headers=dict(resp.headers),
                            )

                    except Exception as exc:
                        log.debug(f"OpenAPI probe failed for {endpoint}: {exc}")

        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "specs_found": specs_found,
            "skipped_cooldown": False,
        }
        log.info("openapi_detector complete", extra=stats)
        return stats
