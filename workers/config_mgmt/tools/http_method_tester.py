"""HTTP method configuration tester — WSTG-CONF-06."""

from __future__ import annotations

import asyncio
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf06")

_SECTION_ID = "WSTG-CONF-06"
_EVIL_ORIGIN = "https://evil.example.com"

_DANGEROUS_METHODS = frozenset({
    "PUT", "DELETE", "PATCH", "COPY", "MOVE", "MKCOL", "LOCK", "UNLOCK", "PROPFIND",
})

_WEBDAV_PATHS = ["/webdav", "/dav", "/webdav/", "/dav/", "/remote.php/webdav"]

_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]

_DB_ASSET_TYPES = ["api_endpoint", "url", "admin_interface", "backup_file"]

_PROBE_SUFFIXES = ["/", "/api", "/api/v1", "/upload", "/files", "/static", "/v1", "/v2"]


# ---------------------------------------------------------------------------
# Pure helper functions — module-level for unit testability
# ---------------------------------------------------------------------------

def _is_dangerous_method(method: str) -> bool:
    """Return True if the method is considered dangerous for open access."""
    return method.upper() in _DANGEROUS_METHODS


def _parse_allow_header(allow_str: str) -> list[str]:
    """Split an Allow header value into a normalized uppercase method list."""
    if not allow_str:
        return []
    return [m.strip().upper() for m in allow_str.split(",") if m.strip()]


def _build_probe_urls(base_url: str, db_urls: list[str]) -> list[str]:
    """Return db_urls if non-empty; otherwise generate fallback paths on base_url."""
    if db_urls:
        return list(db_urls)
    base = base_url.rstrip("/")
    return [base + suffix for suffix in _PROBE_SUFFIXES]


def _classify_method_response(
    method: str, status: int
) -> tuple[str | None, str | None]:
    """Return (severity, description_key) for a method probe response, or (None, None).

    TRACE/TRACK at 200 → medium (XST risk).
    Any dangerous method at 200/201/204 → high.
    All other statuses → not a finding.
    """
    method_upper = method.upper()
    if method_upper in ("TRACE", "TRACK") and status == 200:
        return "medium", "xst_enabled"
    if method_upper in _DANGEROUS_METHODS and status in (200, 201, 204):
        return "high", "method_accepted"
    return None, None


def _classify_cors(
    origin_sent: str, acao: str, acac: str
) -> tuple[str | None, str | None]:
    """Return (severity, vuln_type) for a CORS probe response, or (None, None) if safe.

    Checks:
    - ACAO reflects the evil origin exactly → cors_origin_reflection (high)
    - ACAO=* combined with ACAC=true → cors_wildcard_with_credentials (high)
    - ACAC=true without the above → cors_credentials_without_strict_origin (medium)
    """
    acao_lower = acao.lower().strip()
    acac_lower = acac.lower().strip()

    if acao_lower == origin_sent.lower():
        return "high", "cors_origin_reflection"
    if acao_lower == "*" and acac_lower == "true":
        return "high", "cors_wildcard_with_credentials"
    if acac_lower == "true":
        return "medium", "cors_credentials_without_strict_origin"
    return None, None


# ---------------------------------------------------------------------------
# Async probe coroutines — called from execute()
# ---------------------------------------------------------------------------

async def _probe_methods(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[dict]:
    """Run OPTIONS, TRACE/TRACK, and dangerous-method probes against one URL."""
    results: list[dict] = []
    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    async with sem:
        # OPTIONS — parse Allow header
        try:
            resp = await client.request("OPTIONS", url)
            if resp.status_code == 200:
                allow_raw = (
                    resp.headers.get("allow", "")
                    or resp.headers.get("access-control-allow-methods", "")
                )
                allow = _parse_allow_header(allow_raw)
                if allow:
                    results.append({
                        "observation": {
                            "type": "http_method_config",
                            "value": "OPTIONS_enabled",
                            "details": {"allowed_methods": ", ".join(allow), "location": url},
                        }
                    })
                    for method in allow:
                        if _is_dangerous_method(method):
                            results.append({
                                "vulnerability": {
                                    "name": f"Dangerous HTTP method {method} allowed",
                                    "severity": "medium",
                                    "description": (
                                        f"The {method} method is listed in the Allow header at {url}"
                                    ),
                                    "location": url,
                                    "section_id": _SECTION_ID,
                                }
                            })
        except httpx.RequestError:
            pass

        # TRACE / TRACK — XST
        for method in ("TRACE", "TRACK"):
            try:
                resp = await client.request(method, url)
                severity, _ = _classify_method_response(method, resp.status_code)
                if severity:
                    results.append({
                        "vulnerability": {
                            "name": f"TRACE method enabled (XST) at {url}",
                            "severity": severity,
                            "description": (
                                f"The {method} HTTP method returned HTTP {resp.status_code} "
                                f"at {url}, enabling cross-site tracing attacks"
                            ),
                            "location": url,
                            "section_id": _SECTION_ID,
                        }
                    })
                elif resp.status_code == 405:
                    results.append({
                        "observation": {
                            "type": "http_method_config",
                            "value": "TRACE_disabled",
                            "details": {"method": method, "status": 405, "location": url},
                        }
                    })
            except httpx.RequestError:
                pass

        # Dangerous methods — direct probe
        for method in ("PUT", "DELETE", "PATCH", "COPY", "MOVE"):
            try:
                resp = await client.request(method, url)
                severity, _ = _classify_method_response(method, resp.status_code)
                if severity:
                    results.append({
                        "vulnerability": {
                            "name": f"{method} method accepted at {url}",
                            "severity": severity,
                            "description": (
                                f"The {method} method returned HTTP {resp.status_code} at {url}"
                            ),
                            "location": url,
                            "section_id": _SECTION_ID,
                        }
                    })
            except httpx.RequestError:
                pass

        # WebDAV — only on the root of each origin (avoid duplicate probes)
        if parsed.path in ("", "/"):
            for wdav_path in _WEBDAV_PATHS:
                try:
                    resp = await client.request("PROPFIND", base_origin + wdav_path)
                    if resp.status_code in (200, 207):
                        results.append({
                            "vulnerability": {
                                "name": f"WebDAV enabled at {wdav_path}",
                                "severity": "high",
                                "description": (
                                    f"WebDAV PROPFIND returned HTTP {resp.status_code} "
                                    f"at {base_origin + wdav_path}"
                                ),
                                "location": base_origin + wdav_path,
                                "section_id": _SECTION_ID,
                            }
                        })
                except httpx.RequestError:
                    pass

    return results


async def _probe_method_override(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[dict]:
    """Test method override via headers and query params against the base URL."""
    results: list[dict] = []
    async with sem:
        for header_name in _OVERRIDE_HEADERS:
            try:
                resp = await client.get(base_url, headers={header_name: "DELETE"})
                if resp.status_code in (200, 204):
                    results.append({
                        "vulnerability": {
                            "name": f"HTTP method override via {header_name}",
                            "severity": "high",
                            "description": (
                                f"GET with {header_name}: DELETE returned HTTP "
                                f"{resp.status_code} at {base_url}"
                            ),
                            "location": base_url,
                            "section_id": _SECTION_ID,
                        }
                    })
            except httpx.RequestError:
                pass

        for param_name in ("_method", "method"):
            try:
                resp = await client.get(base_url, params={param_name: "DELETE"})
                if resp.status_code in (200, 204):
                    results.append({
                        "vulnerability": {
                            "name": f"HTTP method override via {param_name} query param",
                            "severity": "high",
                            "description": (
                                f"GET with ?{param_name}=DELETE returned HTTP "
                                f"{resp.status_code} at {base_url}"
                            ),
                            "location": base_url,
                            "section_id": _SECTION_ID,
                        }
                    })
            except httpx.RequestError:
                pass

    return results


async def _probe_cors(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[dict]:
    """Probe one URL for CORS misconfiguration."""
    results: list[dict] = []
    async with sem:
        try:
            resp = await client.get(url, headers={"Origin": _EVIL_ORIGIN})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            severity, vuln_type = _classify_cors(_EVIL_ORIGIN, acao, acac)
            if severity is None:
                return results

            if vuln_type == "cors_origin_reflection":
                results.append({
                    "vulnerability": {
                        "name": f"CORS: arbitrary origin reflected at {url}",
                        "severity": severity,
                        "description": (
                            f"The server reflects the Origin header in "
                            f"Access-Control-Allow-Origin at {url}"
                        ),
                        "location": url,
                        "section_id": _SECTION_ID,
                    }
                })
            elif vuln_type == "cors_wildcard_with_credentials":
                results.append({
                    "vulnerability": {
                        "name": f"CORS: wildcard origin with credentials at {url}",
                        "severity": severity,
                        "description": (
                            f"Access-Control-Allow-Origin: * combined with "
                            f"Access-Control-Allow-Credentials: true at {url}"
                        ),
                        "location": url,
                        "section_id": _SECTION_ID,
                    }
                })
            elif vuln_type == "cors_credentials_without_strict_origin":
                results.append({
                    "vulnerability": {
                        "name": f"CORS: credentials allowed without strict origin at {url}",
                        "severity": severity,
                        "description": (
                            f"Access-Control-Allow-Credentials: true without "
                            f"strict origin validation at {url}"
                        ),
                        "location": url,
                        "section_id": _SECTION_ID,
                    }
                })
        except httpx.RequestError:
            pass

    return results


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------

class HttpMethodTester(ConfigMgmtTool):
    """Test HTTP method configuration per WSTG-CONF-06.

    Phases:
    1. Method enumeration — OPTIONS, TRACE/TRACK, dangerous methods, WebDAV
    2. Method override — X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override
                         and ?_method= / ?method= query params
    3. CORS — origin reflection, wildcard + credentials, credentials alone
    """

    name = "http_method_tester"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("HttpMethodTester uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("HttpMethodTester uses execute() directly")

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, tool=self.name)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0,
                "message": f"{self.name} started",
            })

            # Normalise base URL
            base_url = (
                target.target_value if hasattr(target, "target_value") else str(target)
            )
            if not base_url.startswith(("http://", "https://")):
                base_url = f"https://{base_url.rstrip('/')}"
            else:
                base_url = base_url.rstrip("/")

            scope_result = scope_manager.is_in_scope(base_url)
            if not scope_result.in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # Phase 0 — collect URLs from DB
            async with get_session() as session:
                stmt = select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(_DB_ASSET_TYPES),
                )
                rows = (await session.execute(stmt)).scalars().all()

            db_urls = [u for u in rows if scope_manager.is_in_scope(u).in_scope]
            probe_urls = _build_probe_urls(base_url, db_urls)

            all_results: list[dict] = []

            async with httpx.AsyncClient(
                verify=False, follow_redirects=False,
                timeout=10, headers=headers or {},
            ) as client:
                # Phase 1 — method enumeration across all probe URLs
                p1_sem = asyncio.Semaphore(20)
                p1_tasks = [_probe_methods(client, url, p1_sem) for url in probe_urls]
                for r in await asyncio.gather(*p1_tasks, return_exceptions=True):
                    if isinstance(r, list):
                        all_results.extend(r)

                # Phase 2 — method override on base URL only
                p2_results = await _probe_method_override(
                    client, base_url, asyncio.Semaphore(10)
                )
                all_results.extend(p2_results)

                # Phase 3 — CORS across all probe URLs
                p3_sem = asyncio.Semaphore(20)
                p3_tasks = [_probe_cors(client, url, p3_sem) for url in probe_urls]
                for r in await asyncio.gather(*p3_tasks, return_exceptions=True):
                    if isinstance(r, list):
                        all_results.extend(r)

            found = len(all_results)
            new_count = in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                job = (await session.execute(stmt)).scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {
                "found": found,
                "in_scope": in_scope_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": (
                    f"{self.name}: {new_count} new, "
                    f"{in_scope_count} in scope, {found} total"
                ),
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
