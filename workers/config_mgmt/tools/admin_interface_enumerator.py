"""Admin interface enumeration tool — WSTG-CONF-05."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf05")

_WORDLIST_PATH = "/wordlists/admin-panels.txt"
_HTTP_CONCURRENCY = 20
_SECTION_ID = "WSTG-CONF-05"

_ADMIN_KEYWORDS = frozenset({
    "admin", "administrator", "manage", "manager", "control",
    "console", "panel", "backend", "backoffice", "maintenance",
    "setup", "config", "configure", "cpanel", "webmin", "plesk", "dashboard",
})

_PLATFORM_PATHS: dict[str, list[str]] = {
    "wordpress":  ["/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php"],
    "joomla":     ["/administrator/", "/administrator/index.php"],
    "django":     ["/admin/", "/django-admin/"],
    "laravel":    ["/admin", "/horizon", "/telescope"],
    "spring":     ["/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics"],
    "actuator":   ["/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics"],
    "tomcat":     ["/manager/html", "/host-manager/html"],
    "jenkins":    ["/jenkins", "/blue/organizations/jenkins"],
    "kibana":     ["/kibana", "/app/kibana"],
}


def _load_wordlist(path: str) -> list[str]:
    """Load paths from a wordlist file, deduplicate, strip whitespace, skip comments."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result


def _inject_platform_paths(fingerprints: list[str]) -> list[str]:
    """Return platform-specific admin paths for each detected fingerprint."""
    paths: list[str] = []
    joined = " ".join(fingerprints).lower()
    for keyword, extra in _PLATFORM_PATHS.items():
        if keyword in joined:
            paths.extend(extra)
    return paths


def _classify_200_response(body: str) -> tuple[str, str]:
    """Return (severity, vuln_type) for an HTTP 200 admin path response."""
    if re.search(r'<input[^>]+type\s*=\s*["\']?password', body, re.IGNORECASE):
        return "medium", "admin_interface_exposed"
    return "high", "admin_interface_exposed_unauthenticated"


def _extract_admin_links(html: str, base_url: str) -> list[str]:
    """Parse HTML and return same-origin paths that contain an admin keyword."""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    base_host = urlparse(base_url).netloc
    seen: set[str] = set()
    result: list[str] = []
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if not href:
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.netloc and parsed.netloc != base_host:
            continue
        path = parsed.path
        if not path or path in seen:
            continue
        if any(kw in path.lower() for kw in _ADMIN_KEYWORDS):
            seen.add(path)
            result.append(path)
    return result


def _base_url(target) -> str:
    """Return a normalised base URL string for target."""
    value = getattr(target, "target_value", str(target))
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")
    return f"https://{value.rstrip('/')}"


async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    """GET one path. Return result dict or None."""
    url = base_url + path
    async with sem:
        try:
            resp = await client.get(url)
            status = resp.status_code
            if status == 200:
                body = resp.text
                severity, vuln_type = _classify_200_response(body)
                return {
                    "vulnerability": {
                        "name": f"Admin interface accessible: {path}",
                        "severity": severity,
                        "description": (
                            f"Admin path {url} returned HTTP 200. "
                            f"{'No login form detected — may be accessible without authentication.' if severity == 'high' else 'Login form present.'}"
                        ),
                        "location": url,
                        "section_id": _SECTION_ID,
                    }
                }
            if status in (401, 403):
                return {"observation": {
                    "type": "admin_access_denied",
                    "value": url,
                    "details": {"path": path, "status": status},
                }}
            if status in (301, 302, 307, 308):
                return {"observation": {
                    "type": "admin_redirect",
                    "value": url,
                    "details": {
                        "path": path,
                        "status": status,
                        "location": resp.headers.get("location", ""),
                    },
                }}
        except httpx.RequestError:
            pass
    return None


class AdminInterfaceEnumerator(ConfigMgmtTool):
    """Enumerate admin interfaces via wordlist probing, HTML link mining,
    and auth-header fingerprinting. WSTG-CONF-05."""

    name = "admin_interface_enumerator"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("AdminInterfaceEnumerator uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("AdminInterfaceEnumerator uses execute() directly")

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

            base_url = _base_url(target)

            scope_result = scope_manager.is_in_scope(base_url)
            if not scope_result.in_scope:
                log.info(f"{self.name}: target out of scope — skipping")
                await push_task(f"events:{target_id}", {
                    "event": "TOOL_PROGRESS", "container": container_name,
                    "tool": self.name, "progress": 100,
                    "message": f"{self.name}: out of scope",
                })
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # Phase 0 — DB reads + wordlist
            async with get_session() as session:
                stmt = select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "platform_fingerprint",
                )
                rows = (await session.execute(stmt)).scalars().all()
                fingerprints = list(rows)

            paths = _load_wordlist(_WORDLIST_PATH)
            paths.extend(_inject_platform_paths(fingerprints))
            seen_paths: set[str] = set()
            deduped: list[str] = []
            for p in paths:
                if p not in seen_paths:
                    seen_paths.add(p)
                    deduped.append(p)
            paths = deduped

            inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)
            all_results: list[dict] = []
            realms: list[str] = []

            client_kwargs = dict(
                verify=False, follow_redirects=False, timeout=10,
                headers=headers or {},
            )

            async with httpx.AsyncClient(**client_kwargs) as client:
                # Phase 1 — wordlist probing
                probe_tasks = [
                    _probe_path(client, base_url, p, inner_sem)
                    for p in paths
                ]
                phase1 = await asyncio.gather(*probe_tasks, return_exceptions=True)
                for r in phase1:
                    if isinstance(r, dict):
                        all_results.append(r)
                        if (r.get("observation", {}).get("type") == "admin_access_denied"
                                and r["observation"]["details"].get("status") == 401):
                            realms.append(r["observation"]["value"])

                # Phase 2 — HTML link mining
                for home_path in ("/", "/index"):
                    try:
                        resp = await client.get(base_url + home_path)
                        if resp.status_code == 200:
                            links = _extract_admin_links(resp.text, base_url)
                            link_tasks = [
                                _probe_path(client, base_url, lnk, inner_sem)
                                for lnk in links
                            ]
                            link_results = await asyncio.gather(*link_tasks, return_exceptions=True)
                            for lnk, r in zip(links, link_results):
                                if isinstance(r, Exception):
                                    continue
                                if isinstance(r, dict):
                                    all_results.append(r)
                                elif r is None:
                                    # No finding from probe — record as admin_link observation
                                    all_results.append({"observation": {
                                        "type": "admin_link",
                                        "value": base_url + lnk,
                                        "details": {"path": lnk, "source": "html_mining"},
                                    }})
                    except httpx.RequestError:
                        pass

                # Phase 3 — auth-header fingerprinting on 401 URLs
                for url_401 in realms:
                    try:
                        resp = await client.get(url_401)
                        www_auth = resp.headers.get("www-authenticate", "")
                        if www_auth:
                            realm_match = re.search(r'realm\s*=\s*["\']?([^"\'>,]+)', www_auth, re.I)
                            realm = realm_match.group(1).strip() if realm_match else www_auth
                            all_results.append({"observation": {
                                "type": "auth_realm",
                                "value": url_401,
                                "details": {"realm": realm, "www_authenticate": www_auth},
                            }})
                    except httpx.RequestError:
                        pass

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

            stats = {"found": found, "in_scope": in_scope_count, "new": new_count, "skipped_cooldown": False}
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
