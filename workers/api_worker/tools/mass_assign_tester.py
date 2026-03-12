"""MassAssignTesterTool -- Stage 3 mass assignment vulnerability testing.

Pure-httpx tool that tests POST/PUT/PATCH endpoints for mass assignment
by attempting to set sensitive fields (role, is_admin, etc.) and checking
if the changes persist.
"""

from __future__ import annotations

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass

logger = setup_logger("mass-assign-tester")

SENSITIVE_FIELDS: dict[str, str] = {
    "role": "critical",
    "is_admin": "critical",
    "permissions": "critical",
    "balance": "high",
    "verified": "high",
    "email_confirmed": "high",
    "active": "high",
    "plan": "high",
}


class MassAssignTesterTool(ApiTestTool):
    """Test API endpoints for mass assignment vulnerabilities."""

    name = "mass_assign_tester"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Severity lookup
    # ------------------------------------------------------------------

    def severity_for_field(self, field: str) -> str:
        """Return severity from SENSITIVE_FIELDS dict."""
        return SENSITIVE_FIELDS.get(field, "medium")

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
            log.info("Skipping mass_assign_tester -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        schemas = await self._get_api_schemas(target_id)
        if not schemas:
            log.info("No API schemas found for mass assignment testing")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Filter to POST/PUT/PATCH endpoints
        write_methods = {"POST", "PUT", "PATCH"}
        write_endpoints = [
            s for s in schemas if (s.method or "").upper() in write_methods
        ]
        if not write_endpoints:
            log.info("No write endpoints found for mass assignment testing")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Get base URLs
        api_urls = await self._get_api_urls(target_id)
        if not api_urls:
            api_urls = await self._get_live_urls(target_id)
        if not api_urls:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        client = httpx.AsyncClient(
            timeout=15.0,
            headers=headers or {},
            follow_redirects=True,
        )

        try:
            for schema in write_endpoints:
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

                # Step 1: GET current resource state (if GET is available)
                try:
                    before_resp = await client.get(full_url)
                    if before_resp.status_code != 200:
                        continue
                    try:
                        before_data = before_resp.json()
                    except Exception:
                        continue
                    if not isinstance(before_data, dict):
                        continue
                except Exception as exc:
                    log.debug(f"GET baseline failed for {full_url}: {exc}")
                    continue

                # Step 2: Try to set each sensitive field
                for field, severity in SENSITIVE_FIELDS.items():
                    # Determine a test value
                    if field in ("role", "permissions", "plan"):
                        test_value = "admin"
                    elif field in ("is_admin", "verified", "email_confirmed", "active"):
                        test_value = True
                    elif field == "balance":
                        test_value = 999999
                    else:
                        test_value = "test_value"

                    payload = {field: test_value}

                    try:
                        assign_resp = await client.request(
                            method=schema.method or "POST",
                            url=full_url,
                            json=payload,
                        )
                        if assign_resp.status_code not in (200, 201, 204):
                            continue
                    except Exception as exc:
                        log.debug(f"Mass assign request failed for {field}: {exc}")
                        continue

                    # Step 3: GET again to verify if change stuck
                    try:
                        after_resp = await client.get(full_url)
                        if after_resp.status_code != 200:
                            continue
                        try:
                            after_data = after_resp.json()
                        except Exception:
                            continue
                        if not isinstance(after_data, dict):
                            continue
                    except Exception as exc:
                        log.debug(f"GET verification failed for {full_url}: {exc}")
                        continue

                    # Check if the field was set/changed
                    if field in after_data:
                        before_val = before_data.get(field)
                        after_val = after_data.get(field)
                        if after_val == test_value and before_val != test_value:
                            stats["found"] += 1
                            stats["in_scope"] += 1
                            stats["new"] += 1
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity=severity,
                                title=f"Mass assignment: {field} on {schema.method} {schema.path}",
                                description=(
                                    f"Endpoint {schema.method} {schema.path} accepts "
                                    f"and persists the sensitive field '{field}' "
                                    f"(changed from {before_val!r} to {after_val!r})."
                                ),
                                poc=f"{schema.method} {full_url} with {payload}",
                            )

        finally:
            await client.aclose()

        await self.update_tool_state(target_id, container_name)
        log.info("mass_assign_tester complete", extra=stats)
        return stats
