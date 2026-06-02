"""CSP tester — WSTG-CONF-12."""
from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf12")

_BYPASS_DB_PATH: str = os.environ.get("CSPBYPASS_DATA_PATH", "/cspbypass/data.tsv")


def _load_bypass_db() -> list[tuple[str, str]]:
    try:
        db: list[tuple[str, str]] = []
        with open(_BYPASS_DB_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if "\t" in line:
                    domain, code = line.split("\t", 1)
                else:
                    domain, code = line.strip(), ""
                if domain.strip():
                    db.append((domain.strip().lower(), code.strip()))
        return db
    except FileNotFoundError:
        logger.warning(f"CSPBypass data file not found at {_BYPASS_DB_PATH} — Layer 3 disabled")
        return []
    except Exception as exc:
        logger.warning(f"Failed to load CSPBypass data: {exc} — Layer 3 disabled")
        return []


_BYPASS_DB: list[tuple[str, str]] = _load_bypass_db()

_BARE_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*:$")

_CSP_KEYWORDS = frozenset({
    "'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'",
    "'strict-dynamic'", "'wasm-unsafe-eval'", "'report-sample'",
})

_NONCE_HASH_RE = re.compile(r"^'(?:nonce-|sha(?:256|384|512)-)", re.IGNORECASE)


def _parse_csp_source(token: str) -> dict | None:
    if _BARE_SCHEME_RE.match(token):
        return None

    scheme = None
    rest = token
    if "://" in token:
        scheme, rest = token.split("://", 1)

    path_prefix = None
    if "/" in rest:
        idx = rest.index("/")
        host_port = rest[:idx]
        path_prefix = rest[idx:]
    else:
        host_port = rest

    if host_port.count(":") == 1:
        host_port = host_port.rsplit(":", 1)[0]

    wildcard_subdomain = False
    if host_port.startswith("*."):
        wildcard_subdomain = True
        host_port = host_port[2:]

    host = host_port.strip()
    if not host:
        return None

    return {
        "scheme": scheme,
        "host": host,
        "wildcard_subdomain": wildcard_subdomain,
        "path_prefix": path_prefix,
    }

_SECTION_ID = "WSTG-CONF-12"
_DB_ASSET_TYPES = ["domain", "subdomain", "url", "endpoint"]


def _parse_csp_header(header: str) -> dict:
    """Tokenize a CSP header string into {directive: [sources]}."""
    if not header:
        return {}
    policy: dict[str, list[str]] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        policy[directive] = [s.lower() for s in tokens[1:]]
    return policy


def _classify_directives(host: str, url: str, policy: dict) -> list[dict]:
    """Return vulnerability/observation dicts for every CSP weakness in policy."""
    if not policy:
        return [{"vulnerability": {
            "name": f"Missing Content-Security-Policy header on {url}",
            "severity": "high",
            "description": (
                f"No Content-Security-Policy HTTP header found on {url}. "
                "Without CSP, browsers apply no resource loading restrictions, "
                "leaving the page exposed to XSS and injection attacks."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }}]

    results: list[dict] = []

    # Effective script-src: explicit directive wins; absent → fall back to default-src
    script_src = (
        policy["script-src"] if "script-src" in policy
        else policy.get("default-src", [])
    )
    style_src = (
        policy["style-src"] if "style-src" in policy
        else policy.get("default-src", [])
    )
    default_src = policy.get("default-src")

    # ── High ──────────────────────────────────────────────────────────────────

    if "'unsafe-inline'" in script_src:
        results.append({"vulnerability": {
            "name": f"CSP allows unsafe-inline scripts on {host}",
            "severity": "high",
            "description": (
                f"'unsafe-inline' in script-src on {url} permits arbitrary inline "
                "script execution, defeating CSP's primary XSS protection."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    if "'unsafe-eval'" in script_src:
        results.append({"vulnerability": {
            "name": f"CSP allows unsafe-eval on {host}",
            "severity": "high",
            "description": (
                f"'unsafe-eval' in script-src on {url} enables eval() and similar "
                "dynamic code execution, weakening CSP protections."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    if "*" in script_src:
        results.append({"vulnerability": {
            "name": f"CSP wildcard script source on {host}",
            "severity": "high",
            "description": (
                f"Wildcard '*' in script-src on {url} allows scripts from any origin, "
                "rendering the CSP ineffective against XSS."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    seen_insecure_schemes: set[str] = set()
    for src in script_src:
        if src in ("http:", "data:") and src not in seen_insecure_schemes:
            seen_insecure_schemes.add(src)
            results.append({"vulnerability": {
                "name": f"CSP allows insecure script source scheme on {host}",
                "severity": "high",
                "description": (
                    f"'{src}' in script-src on {url} allows scripts from insecure or "
                    "data-URI sources, enabling injection attacks."
                ),
                "location": url,
                "section_id": _SECTION_ID,
            }})

    # ── Medium ────────────────────────────────────────────────────────────────

    if "*" in style_src:
        results.append({"vulnerability": {
            "name": f"CSP wildcard style source on {host}",
            "severity": "medium",
            "description": (
                f"Wildcard '*' in style-src on {url} allows stylesheets from any origin, "
                "enabling CSS injection attacks."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    if "'unsafe-inline'" in style_src:
        results.append({"vulnerability": {
            "name": f"CSP allows unsafe-inline styles on {host}",
            "severity": "medium",
            "description": (
                f"'unsafe-inline' in style-src on {url} permits arbitrary inline style injection."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    if default_src is None:
        results.append({"vulnerability": {
            "name": f"CSP missing default-src on {host}",
            "severity": "medium",
            "description": (
                f"No default-src in CSP on {url}. Fetch directives without an explicit "
                "value are unrestricted."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    if "object-src" not in policy and default_src is not None:
        results.append({"vulnerability": {
            "name": f"CSP missing object-src on {host}",
            "severity": "medium",
            "description": (
                f"No object-src directive in CSP on {url}. "
                "Even with default-src set, plugin content (Flash, Java applets) "
                "is not explicitly restricted — object-src must be set explicitly."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})

    # ── Low ───────────────────────────────────────────────────────────────────

    for directive in ("img-src", "font-src"):
        src_list = (
            policy[directive] if directive in policy
            else policy.get("default-src", [])
        )
        if "*" in src_list:
            results.append({"vulnerability": {
                "name": f"CSP wildcard media source on {host}",
                "severity": "low",
                "description": (
                    f"Wildcard '*' in {directive} on {url} allows media from any origin."
                ),
                "location": url,
                "section_id": _SECTION_ID,
            }})
            break

    if not results:
        results.append({"observation": {
            "type": "csp_config",
            "value": "compliant",
            "details": {"host": host, "url": url, "policy": policy},
        }})

    return results


def _scan_meta_tag(host: str, url: str, html: str) -> list[dict]:
    """Parse HTML body for <meta http-equiv="Content-Security-Policy"> tags."""
    results: list[dict] = []
    for meta_m in re.finditer(r"<meta\b[^>]*>", html, re.IGNORECASE | re.DOTALL):
        tag = meta_m.group(0)
        if not re.search(r"http-equiv=[\"']?Content-Security-Policy[\"']?", tag, re.IGNORECASE):
            continue
        # Handle both double-quoted and single-quoted content attribute
        content_m = re.search(r'content="([^"]*)"', tag, re.IGNORECASE) or \
                    re.search(r"content='([^']*)'", tag, re.IGNORECASE)
        if not content_m:
            continue
        meta_policy_str = content_m.group(1)
        results.append({"vulnerability": {
            "name": f"CSP delivered via meta tag on {host}",
            "severity": "low",
            "description": (
                f"Content-Security-Policy found in an HTML <meta> tag on {url}. "
                "Meta-tag CSP cannot restrict navigation requests, form-action in some "
                "browsers, or worker-src, and is ignored by older user agents. "
                "Use the HTTP response header instead."
            ),
            "location": url,
            "section_id": _SECTION_ID,
        }})
        meta_policy = _parse_csp_header(meta_policy_str)
        if meta_policy:
            results.extend(_classify_directives(host, url, meta_policy))
    return results


# ---------------------------------------------------------------------------
# Google CSP Evaluator helper
# ---------------------------------------------------------------------------

_GOOGLE_CSP_EVAL_URL = "https://csp-evaluator.withgoogle.com/getCSPEvaluation"
_GOOGLE_SEVERITY: dict[int, str] = {10: "high", 20: "medium", 30: "low"}


async def _call_google_csp_evaluator(policy_str: str, url: str) -> list[dict]:
    """POST policy to Google CSP Evaluator API; return mapped vuln dicts."""
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.post(_GOOGLE_CSP_EVAL_URL, json={"csp": policy_str})
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"Google CSP Evaluator API failed for {url}: {exc}")
        return []

    results: list[dict] = []
    for finding in data.get("findings", []):
        severity = _GOOGLE_SEVERITY.get(finding.get("severity", 99))
        if severity is None:
            continue
        directive = finding.get("directive", "")
        description = finding.get("description", "")
        results.append({"vulnerability": {
            "name": f"Google CSP Evaluator [{directive}]: {description[:60]}",
            "severity": severity,
            "description": f"Google CSP Evaluator finding on {url}: {description}",
            "location": url,
            "section_id": _SECTION_ID,
        }})
    return results


# ---------------------------------------------------------------------------
# cspbypass helper
# ---------------------------------------------------------------------------

async def _run_csp_bypass(url: str) -> list[dict]:
    """Invoke cspbypass CLI against url; map each bypass line to a high vuln."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "cspbypass", url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning(f"cspbypass timed out for {url}")
            return []
        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
    except FileNotFoundError:
        logger.error("cspbypass binary not found — skipping Layer 3")
        return []

    results: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append({"vulnerability": {
            "name": f"CSP bypass technique: {line[:80]}",
            "severity": "high",
            "description": f"cspbypass detected a bypass technique on {url}: {line}",
            "location": url,
            "section_id": _SECTION_ID,
        }})
    return results


# ---------------------------------------------------------------------------
# Per-URL probe coroutine
# ---------------------------------------------------------------------------

async def _probe_url(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[dict]:
    """GET url once; run all three analysis layers; return all findings."""
    async with sem:
        try:
            resp = await client.get(url)
        except httpx.RequestError:
            return []

        csp_header = resp.headers.get("content-security-policy", "")
        html = resp.text
        host = urlparse(url).netloc or url

        results: list[dict] = []

        # Layer 1 — own directive classifier (handles missing-header case via empty policy)
        results.extend(_classify_directives(host, url, _parse_csp_header(csp_header)))

        # Layers 2 + 3 only when a policy exists to evaluate / bypass
        if csp_header:
            results.extend(await _call_google_csp_evaluator(csp_header, url))
            results.extend(await _run_csp_bypass(url))

        # Meta tag scan — always, regardless of HTTP header
        results.extend(_scan_meta_tag(host, url, html))

        return results


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------

class CspTester(ConfigMgmtTool):
    """Test Content Security Policy per WSTG-CONF-12.

    Probes every domain, subdomain, url, and endpoint asset from DB.
    Three analysis layers: own classifier, Google CSP Evaluator API, cspbypass CLI.
    """

    name = "csp_tester"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("CspTester uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("CspTester uses execute() directly")

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
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 0,
                "message": f"{self.name} started",
            })

            # Resolve base URL for fallback
            raw = target.target_value if hasattr(target, "target_value") else str(target)
            if not raw.startswith(("http://", "https://")):
                raw = f"https://{raw}"

            # Collect probe targets from DB
            async with get_session() as session:
                stmt = select(Asset.asset_value, Asset.asset_type).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(_DB_ASSET_TYPES),
                )
                rows = (await session.execute(stmt)).all()

            probe_urls: list[str] = []
            for value, asset_type in rows:
                if asset_type in ("domain", "subdomain"):
                    candidate = f"https://{value}/"
                else:
                    candidate = (
                        value if value.startswith(("http://", "https://"))
                        else f"https://{value}"
                    )
                if scope_manager.is_in_scope(candidate).in_scope:
                    probe_urls.append(candidate)

            if not probe_urls:
                probe_urls = [raw]

            # Deduplicate while preserving order
            seen: set[str] = set()
            unique_urls = [u for u in probe_urls if not (u in seen or seen.add(u))]

            all_results: list[dict] = []
            probe_sem = asyncio.Semaphore(10)

            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=15,
                headers=headers or {},
            ) as client:
                tasks = [_probe_url(client, u, probe_sem) for u in unique_urls]
                for r in await asyncio.gather(*tasks, return_exceptions=True):
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
