"""NewmanProber — Stage 6 API endpoint probing via Newman (Postman CLI).

Auto-generates a Postman collection from discovered endpoints and runs
it via Newman to probe for auth issues, verbose errors, and unexpected
responses.
"""

from __future__ import annotations

import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("newman-prober")

# HTTP methods to probe each endpoint with.
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]

# Postman collection schema.
POSTMAN_SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"


class NewmanProber(WebAppTool):
    """Probe discovered API endpoints using Newman (Postman CLI runner)."""

    name = "newman_prober"
    tool_type = ToolType.CLI
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _build_collection(endpoints: list[str], target_name: str) -> dict:
        """Generate a Postman collection dict from a list of endpoint URLs.

        Each endpoint is tested with GET, POST, PUT, and DELETE.
        """
        items = []
        for url in endpoints:
            for method in HTTP_METHODS:
                items.append({
                    "name": f"{method} {url}",
                    "request": {
                        "method": method,
                        "url": {"raw": url},
                        "header": [],
                    },
                })

        return {
            "info": {
                "name": f"WebAppBH Auto-Collection: {target_name}",
                "schema": POSTMAN_SCHEMA,
            },
            "item": items,
        }

    async def _get_endpoints(self, target_id: int) -> list[str]:
        """Query discovered URL assets for the target."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["url", "domain"]),
            )
            result = await session.execute(stmt)
            return [row[0] for row in result.all()]

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run Newman against discovered endpoints.

        Returns a stats dict with keys: endpoints_probed, findings,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="newman")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping newman_prober — within cooldown period")
            return {"endpoints_probed": 0, "findings": 0, "skipped_cooldown": True}

        # Get discovered endpoints
        endpoints = await self._get_endpoints(target_id)
        if not endpoints:
            log.info("No endpoints discovered — skipping newman")
            return {"endpoints_probed": 0, "findings": 0, "skipped_cooldown": False}

        # Build and write collection
        target_name = getattr(target, "base_domain", str(target_id))
        collection = self._build_collection(endpoints, target_name)

        tmpdir = tempfile.mkdtemp(prefix="newman_")
        collection_path = os.path.join(tmpdir, "collection.json")
        output_path = os.path.join(tmpdir, "results.json")

        try:
            with open(collection_path, "w") as f:
                json.dump(collection, f)

            # Run newman
            cmd = [
                "newman", "run", collection_path,
                "--reporters", "json",
                "--reporter-json-export", output_path,
            ]
            await self.run_subprocess(cmd)

            # Parse results
            findings = 0
            if os.path.isfile(output_path):
                with open(output_path, "r") as f:
                    results = json.load(f)

                executions = results.get("run", {}).get("executions", [])
                urls = await self._get_live_urls(target_id)
                asset_id = urls[0][0] if urls else 0

                for execution in executions:
                    response = execution.get("response", {})
                    status_code = response.get("code", 0)
                    req = execution.get("item", {}).get("request", {})
                    req_url = req.get("url", {}).get("raw", "unknown")
                    req_method = req.get("method", "GET")

                    # Flag interesting responses
                    if status_code == 401:
                        # Auth required — save as observation
                        await self._save_observation(
                            asset_id=asset_id,
                            status_code=status_code,
                            page_title=None,
                            tech_stack={"endpoint": req_url, "method": req_method},
                            headers=None,
                        )
                    elif status_code == 403:
                        await self._save_observation(
                            asset_id=asset_id,
                            status_code=status_code,
                            page_title=None,
                            tech_stack={"endpoint": req_url, "method": req_method},
                            headers=None,
                        )
                    elif status_code == 500:
                        # Server error — potential info disclosure
                        body = response.get("body", "")
                        if any(kw in body.lower() for kw in ["traceback", "exception", "error", "stack"]):
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title=f"Verbose error on {req_method} {req_url}",
                                description=(
                                    f"The endpoint {req_url} ({req_method}) returned "
                                    f"a 500 error with verbose error details that may "
                                    f"leak internal information."
                                ),
                                poc=f"{req_method} {req_url}",
                            )
                            findings += 1
                    elif status_code == 200 and req_method in ("PUT", "DELETE"):
                        # Successful write/delete without auth
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=f"Unauthenticated {req_method} on {req_url}",
                            description=(
                                f"The endpoint {req_url} accepted a {req_method} "
                                f"request without authentication and returned 200."
                            ),
                            poc=f"{req_method} {req_url}",
                        )
                        findings += 1

        except Exception as exc:
            log.warning(f"Newman execution failed: {exc}")
        finally:
            # Cleanup temp files
            for path in (collection_path, output_path):
                if os.path.isfile(path):
                    os.unlink(path)
            if os.path.isdir(tmpdir):
                os.rmdir(tmpdir)

        await self.update_tool_state(target_id, container_name)

        stats = {
            "endpoints_probed": len(endpoints),
            "findings": findings,
            "skipped_cooldown": False,
        }
        log.info("newman_prober complete", extra=stats)
        return stats
