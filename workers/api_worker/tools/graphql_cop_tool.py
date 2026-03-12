"""GraphqlCopTool -- Stage 4 GraphQL security audit with graphql-cop.

Wraps graphql-cop CLI to detect GraphQL-specific security issues like
introspection enabled, batch queries, field suggestions, and more.
"""

from __future__ import annotations

import json

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("graphql-cop")


class GraphqlCopTool(ApiTestTool):
    """Audit GraphQL endpoints for security issues using graphql-cop."""

    name = "graphql_cop"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> list[dict]:
        """Parse graphql-cop JSON array output.

        Returns list of finding dicts with: title, severity, description.
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        if not isinstance(data, list):
            return []
        return data

    # ------------------------------------------------------------------
    # Severity mapping
    # ------------------------------------------------------------------

    def map_severity(self, cop_sev: str) -> str:
        """Map graphql-cop severity strings to our severity levels."""
        mapping = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }
        return mapping.get(cop_sev.upper(), "info")

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
            log.info("Skipping graphql_cop -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        schemas = await self._get_api_schemas(target_id)
        if not schemas:
            log.info("No API schemas found for GraphQL scanning")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Filter to GraphQL endpoints
        graphql_schemas = [s for s in schemas if s.spec_type == "graphql"]
        if not graphql_schemas:
            log.info("No GraphQL endpoints found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Get base URLs for URL construction
        api_urls = await self._get_api_urls(target_id)
        if not api_urls:
            api_urls = await self._get_live_urls(target_id)
        if not api_urls:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        sem = get_semaphore(self.weight_class)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Deduplicate GraphQL endpoints by asset_id
        seen_assets: set[int | None] = set()

        for schema in graphql_schemas:
            asset_id = schema.asset_id
            if asset_id in seen_assets:
                continue
            seen_assets.add(asset_id)

            # Determine target URL
            target_url = None
            for aid, url_val in api_urls:
                if aid == asset_id:
                    target_url = url_val if url_val.startswith("http") else f"https://{url_val}"
                    break
            if target_url is None:
                target_url = api_urls[0][1]
                if not target_url.startswith("http"):
                    target_url = f"https://{target_url}"
                asset_id = api_urls[0][0]

            # Ensure URL points to graphql endpoint
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            if "/graphql" not in parsed.path.lower():
                graphql_url = f"{parsed.scheme}://{parsed.netloc}/graphql"
            else:
                graphql_url = target_url

            cmd = [
                "python3", "/opt/graphql-cop/graphql-cop.py",
                "-t", graphql_url,
                "-o", "json",
            ]

            await sem.acquire()
            try:
                try:
                    stdout = await self.run_subprocess(cmd)
                except Exception as exc:
                    log.error(f"graphql-cop failed for {graphql_url}: {exc}")
                    continue
            finally:
                sem.release()

            findings = self.parse_output(stdout)
            stats["found"] += len(findings)

            for finding in findings:
                title = finding.get("title", "Unknown GraphQL issue")
                cop_severity = finding.get("severity", "INFO")
                description = finding.get("description", "")
                severity = self.map_severity(cop_severity)

                if asset_id is not None:
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity=severity,
                        title=f"GraphQL: {title}",
                        description=f"{description} (endpoint: {graphql_url})",
                        poc=f"graphql-cop -t {graphql_url}",
                    )

        await self.update_tool_state(target_id, container_name)
        log.info("graphql_cop complete", extra=stats)
        return stats
