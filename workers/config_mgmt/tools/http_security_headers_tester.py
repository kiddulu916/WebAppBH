"""HTTP security header misconfiguration tester — WSTG-CONF-14."""
from __future__ import annotations

import asyncio
from datetime import datetime

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf14")

_SECTION_ID = "WSTG-CONF-14"
_HTTP_CONCURRENCY = 20
_CORS_PROBE_ORIGIN = "https://cors-probe.invalid"
_PHASE1_ASSET_TYPES = ["domain", "subdomain"]
_PHASE2_ASSET_TYPES = ["url", "endpoint", "page"]


def _classify_static_headers(host: str, headers: dict) -> list[dict]:
    """Classify static security headers on https://{host}/ response."""
    findings: list[dict] = []
    loc = f"https://{host}/"

    xfo = headers.get("x-frame-options", "")
    if not xfo:
        findings.append({"vulnerability": {
            "name": f"Missing X-Frame-Options on {host}",
            "severity": "low",
            "description": (
                f"The X-Frame-Options header is absent on {host}. "
                "Without it, the page may be embedded in a cross-origin iframe, "
                "enabling clickjacking attacks. Use DENY or SAMEORIGIN."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})
    elif "allow-from" in xfo.lower():
        findings.append({"vulnerability": {
            "name": f"Deprecated X-Frame-Options ALLOW-FROM on {host}",
            "severity": "low",
            "description": (
                f"X-Frame-Options on {host} uses the deprecated ALLOW-FROM directive "
                f"(value: {xfo!r}). ALLOW-FROM is not supported by modern browsers. "
                "Use Content-Security-Policy frame-ancestors instead."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})

    xcto = headers.get("x-content-type-options")
    if xcto is None:
        findings.append({"vulnerability": {
            "name": f"Missing X-Content-Type-Options on {host}",
            "severity": "low",
            "description": (
                f"The X-Content-Type-Options header is absent on {host}. "
                "Browsers may perform MIME-type sniffing on responses, "
                "potentially interpreting a text response as an executable script."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})
    elif xcto.strip().lower() != "nosniff":
        findings.append({"vulnerability": {
            "name": f"Invalid X-Content-Type-Options on {host}",
            "severity": "medium",
            "description": (
                f"X-Content-Type-Options on {host} is set to {xcto!r} instead of "
                "'nosniff'. The only valid value is 'nosniff'. This misconfiguration "
                "leaves MIME-type sniffing enabled."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})

    rp = headers.get("referrer-policy", "")
    if not rp:
        findings.append({"vulnerability": {
            "name": f"Missing Referrer-Policy on {host}",
            "severity": "info",
            "description": (
                f"No Referrer-Policy header is set on {host}. "
                "Without it, browsers use their default referrer behaviour, "
                "which may send the full URL as a Referer header to third-party origins."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})
    elif rp.strip().lower() == "unsafe-url":
        findings.append({"vulnerability": {
            "name": f"Unsafe Referrer-Policy on {host}",
            "severity": "medium",
            "description": (
                f"Referrer-Policy on {host} is set to 'unsafe-url', which sends the "
                "full URL (including path and query string) as a Referer header on "
                "every request, including cross-origin ones. This leaks sensitive "
                "URL parameters to third parties."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})

    pp = headers.get("permissions-policy")
    if pp is None:
        findings.append({"vulnerability": {
            "name": f"Missing Permissions-Policy on {host}",
            "severity": "info",
            "description": (
                f"No Permissions-Policy header is set on {host}. "
                "Without it, embedded content may access browser features "
                "(camera, geolocation, microphone, etc.) without restriction."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})
    elif not pp.strip():
        findings.append({"vulnerability": {
            "name": f"Empty Permissions-Policy on {host}",
            "severity": "low",
            "description": (
                f"The Permissions-Policy header on {host} is present but empty. "
                "An empty value provides no policy enforcement. Set explicit "
                "directives to restrict feature access."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})

    xpcdp = headers.get("x-permitted-cross-domain-policies", "")
    if not xpcdp:
        findings.append({"vulnerability": {
            "name": f"Missing X-Permitted-Cross-Domain-Policies on {host}",
            "severity": "info",
            "description": (
                f"No X-Permitted-Cross-Domain-Policies header is set on {host}. "
                "Without it, Adobe Flash and PDF readers may load cross-domain policy "
                "files, potentially accessing content from this domain."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})
    elif xpcdp.strip().lower() in ("all", "master-only"):
        findings.append({"vulnerability": {
            "name": f"Permissive X-Permitted-Cross-Domain-Policies on {host}",
            "severity": "medium",
            "description": (
                f"X-Permitted-Cross-Domain-Policies on {host} is set to {xpcdp!r}. "
                "This allows Adobe Flash and PDF readers to make cross-domain requests "
                "that could read sensitive content. Set to 'none' to block all "
                "cross-domain policy files."
            ),
            "location": loc,
            "section_id": _SECTION_ID,
        }})

    return findings


def _classify_cors(url: str, headers: dict) -> list[dict]:
    """Classify CORS headers on a URL response."""
    acao = headers.get("access-control-allow-origin", "")
    if acao.strip() != "*":
        return []

    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    if acac == "true":
        return [{"vulnerability": {
            "name": f"CORS wildcard origin with credentials enabled: {url}",
            "severity": "high",
            "description": (
                f"The response from {url} sets Access-Control-Allow-Origin: * "
                "and Access-Control-Allow-Credentials: true. This combination allows "
                "any origin to make credentialed cross-origin requests (with cookies "
                "or HTTP auth), potentially exposing authenticated user data."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }}]

    return [{"vulnerability": {
        "name": f"CORS wildcard origin on {url}",
        "severity": "medium",
        "description": (
            f"The response from {url} sets Access-Control-Allow-Origin: *, "
            "allowing any origin to read the response. For endpoints serving "
            "user-specific data this exposes sensitive information to any "
            "cross-origin request."
        ),
        "location": url,
        "section_id": _SECTION_ID,
    }}]


class HttpSecurityHeadersTester(ConfigMgmtTool):
    """Test HTTP security header misconfigurations per WSTG-CONF-14."""

    name = "http_security_headers_tester"

    def build_command(self, target, headers=None):
        raise NotImplementedError("HttpSecurityHeadersTester uses execute() directly")

    def parse_output(self, stdout):
        raise NotImplementedError("HttpSecurityHeadersTester uses execute() directly")

    async def _fetch_phase1_hosts(self, target_id: int) -> list[str]:
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(_PHASE1_ASSET_TYPES),
            )
            rows = (await session.execute(stmt)).scalars().all()
        return [r for r in rows if r]

    async def _fetch_phase2_urls(self, target_id: int) -> list[str]:
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(_PHASE2_ASSET_TYPES),
            )
            rows = (await session.execute(stmt)).scalars().all()
        seen: set[str] = set()
        urls: list[str] = []
        for v in rows:
            if v and v not in seen:
                seen.add(v)
                urls.append(v)
        return urls

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
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 0,
                "message": f"{self.name} started",
            })

            inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)
            all_findings: list[dict] = []

            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=False,
                timeout=10,
                headers=headers or {},
            ) as client:
                p1_hosts = await self._fetch_phase1_hosts(target_id)
                p1_hosts = [
                    h for h in p1_hosts
                    if scope_manager.is_in_scope(f"https://{h}").in_scope
                ]
                p1_results = await asyncio.gather(
                    *[self._probe_static(client, inner_sem, h, log) for h in p1_hosts],
                    return_exceptions=True,
                )
                for r in p1_results:
                    if isinstance(r, Exception):
                        log.warning("static probe raised exception", extra={"error": str(r)})
                    elif isinstance(r, list):
                        all_findings.extend(r)

                p2_urls = await self._fetch_phase2_urls(target_id)
                p2_urls = [
                    u for u in p2_urls
                    if scope_manager.is_in_scope(u).in_scope
                ]
                p2_results = await asyncio.gather(
                    *[self._probe_cors(client, inner_sem, u, log) for u in p2_urls],
                    return_exceptions=True,
                )
                for r in p2_results:
                    if isinstance(r, Exception):
                        log.warning("CORS probe raised exception", extra={"error": str(r)})
                    elif isinstance(r, list):
                        all_findings.extend(r)

            found = len(all_findings)
            new_count = in_scope_count = 0
            for finding in all_findings:
                inserted = await self._process_result(finding, scope_manager, target_id, log)
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
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": (
                    f"{self.name}: {new_count} new, "
                    f"{in_scope_count} in scope, {found} total"
                ),
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()

    async def _probe_static(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        host: str,
        log,
    ) -> list[dict]:
        async with sem:
            try:
                resp = await client.get(f"https://{host}/")
            except httpx.RequestError as exc:
                log.debug(f"Static probe failed for {host}: {exc}")
                return []
        return _classify_static_headers(host, dict(resp.headers))

    async def _probe_cors(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
        log,
    ) -> list[dict]:
        async with sem:
            try:
                resp = await client.get(url, headers={"Origin": _CORS_PROBE_ORIGIN})
            except httpx.RequestError as exc:
                log.debug(f"CORS probe failed for {url}: {exc}")
                return []
        if resp.status_code != 200:
            return []
        return _classify_cors(url, dict(resp.headers))
