"""FfufApiTool -- Stage 1 API endpoint brute-forcing with ffuf.

Different from config_mgmt's FfufTool: this one cycles through
HTTP methods (GET, POST, PUT, DELETE) per API root and uses
API-specific wordlists.  Discovered routes are saved to api_schemas
and 401/403 endpoints are flagged with auth_required=True.
"""

from __future__ import annotations

import json
import os
import tempfile
from urllib.parse import urlparse

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("ffuf-api-tool")

API_WORDLIST = os.environ.get(
    "API_WORDLIST", "/app/wordlists/api-endpoints.txt"
)
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE")


class FfufApiTool(ApiTestTool):
    """Brute-force API endpoints using ffuf with multiple HTTP methods."""

    name = "ffuf_api"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

    def build_command(
        self,
        url: str,
        wordlist: str,
        rate_limit: int,
        method: str = "GET",
        headers: dict | None = None,
        output_file: str = "/tmp/ffuf.json",
    ) -> list[str]:
        """Build the ffuf CLI command list."""
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-o", output_file,
            "-of", "json",
            "-X", method,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-rate", str(rate_limit),
            "-t", str(min(rate_limit, 50)),
        ]
        if method in ("POST", "PUT", "PATCH"):
            cmd.extend(["-H", "Content-Type: application/json"])
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])
        return cmd

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> list[dict]:
        """Parse ffuf JSON output, return list of result dicts."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return data.get("results", [])

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
            log.info("Skipping ffuf_api -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # Prefer known API URLs; fall back to all live URLs
        urls = await self._get_api_urls(target_id)
        if not urls:
            urls = await self._get_live_urls(target_id)
        if not urls:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)
        wordlist = API_WORDLIST

        sem = get_semaphore(self.weight_class)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for asset_id, domain in urls:
            # Normalise base URL
            base_url = domain if domain.startswith("http") else f"https://{domain}"
            fuzz_url = f"{base_url}/FUZZ"

            for method in HTTP_METHODS:
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                    out_file = tmp.name

                cmd = self.build_command(
                    fuzz_url, wordlist, rate_limit, method, headers, out_file,
                )

                raw = ""
                await sem.acquire()
                try:
                    try:
                        await self.run_subprocess(cmd)
                    except Exception as exc:
                        log.error(f"ffuf_api failed on {domain} [{method}]: {exc}")
                        continue
                    finally:
                        if os.path.exists(out_file):
                            with open(out_file) as fh:
                                raw = fh.read()
                            os.unlink(out_file)
                finally:
                    sem.release()

                results = self.parse_output(raw)
                stats["found"] += len(results)

                for entry in results:
                    url = entry.get("url", "")
                    status = entry.get("status", 0)
                    length = entry.get("length", 0)

                    saved_id = await self._save_asset(
                        target_id, url, scope_manager, source_tool="ffuf_api",
                    )
                    if saved_id is None:
                        continue

                    stats["in_scope"] += 1
                    stats["new"] += 1

                    auth_required = status in (401, 403)

                    parsed = urlparse(url)
                    path = parsed.path or "/"

                    await self._save_api_schema(
                        target_id=target_id,
                        asset_id=saved_id,
                        method=method,
                        path=path,
                        auth_required=auth_required,
                        source_tool="ffuf_api",
                        spec_type="discovered",
                    )

                    # Flag restricted endpoints as informational vuln
                    if auth_required:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=saved_id,
                            severity="info",
                            title=f"API auth required: {method} {path}",
                            description=(
                                f"HTTP {status} at {url} — endpoint requires "
                                f"authentication. Potential bypass target."
                            ),
                            poc=url,
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("ffuf_api complete", extra=stats)
        return stats
