# workers/info_gathering/tools/app_path_enumerator.py
"""AppPathEnumerator — probe target for applications at non-standard URL paths."""

import json
import os
import tempfile

from workers.info_gathering.base_tool import InfoGatheringTool, TOOL_TIMEOUT, logger

# Application-level path prefixes that commonly host distinct sub-applications.
# Focused on app-level entry points, not generic file/directory brute-forcing.
APP_PATHS: list[str] = [
    "admin", "portal", "webmail", "mail", "email", "dashboard", "api", "app",
    "backend", "console", "management", "wp-admin", "phpmyadmin", "cpanel",
    "login", "secure", "internal", "dev", "staging", "test", "demo", "backup",
    "monitor", "status", "health", "swagger", "graphql", "redoc", "docs",
    "api-docs", "helpdesk", "support", "crm", "erp", "git", "gitlab", "jira",
    "confluence", "jenkins", "sonar", "kibana", "grafana", "prometheus", "vault",
    "registry", "nexus", "artifactory", "wiki", "intranet", "vpn", "remote",
    "access", "connect", "extranet", "partner", "client", "customer", "shop",
    "store", "cart", "checkout", "payment", "billing", "invoice", "account",
    "profile", "settings", "config", "panel", "control", "manage", "report",
    "analytics", "metrics", "log", "logs", "audit", "trace", "debug", "error",
    "exception", "system", "service", "api-v1", "api-v2", "v1", "v2", "v3",
    "rest", "rpc", "soap", "graphiql",
]

# HTTP status codes that confirm a real application is present.
# 401/403 indicate access-controlled apps; 404 is excluded (nothing there).
HIT_CODES: set[int] = {200, 201, 301, 302, 307, 308, 401, 403}


class AppPathEnumerator(InfoGatheringTool):
    """Probe the target domain for distinct applications at non-standard path prefixes.

    Uses ffuf with a curated wordlist. Only persists paths that return meaningful
    HTTP responses (HIT_CODES), distinguishing real apps from 404s.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        scope_manager = kwargs.get("scope_manager")
        host = kwargs.get("host") or (target.base_domain if target else None)
        if not host:
            return {"found": 0}

        wordlist_path = None
        output_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as wl:
                wl.write("\n".join(APP_PATHS))
                wordlist_path = wl.name

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
                output_path = out.name

            cmd = [
                "ffuf",
                "-u", f"https://{host}/FUZZ",
                "-w", wordlist_path,
                "-mc", ",".join(str(c) for c in sorted(HIT_CODES)),
                "-o", output_path,
                "-of", "json",
                "-t", "20",
                "-timeout", "10",
                "-s",
            ]
            try:
                await self.run_subprocess(cmd, timeout=TOOL_TIMEOUT)
            except Exception as exc:
                logger.warning(f"AppPathEnumerator: ffuf failed for {host}: {exc}")
                return {"found": 0}

            return await self._parse_and_save(target_id, output_path, host, scope_manager)
        finally:
            for path in (wordlist_path, output_path):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    async def _parse_and_save(
        self, target_id: int, output_path: str, host: str, scope_manager
    ) -> dict:
        """Parse ffuf JSON output and persist hit paths as Assets + Observations."""
        try:
            with open(output_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"found": 0}

        saved = 0
        for hit in data.get("results", []):
            status = hit.get("status")
            if status not in HIT_CODES:
                continue
            url = hit.get("url", "")
            if not url:
                continue

            asset_id = await self.save_asset(
                target_id, "url", url, "app_path_enumerator",
                scope_manager=scope_manager,
            )
            if not asset_id:
                continue

            await self.save_observation(
                asset_id,
                status_code=status,
                headers={
                    "content_length": hit.get("length", 0),
                    "redirect_url": hit.get("redirectlocation", ""),
                },
            )
            saved += 1

        return {"found": saved}
