"""CSP tester — WSTG-CONF-12."""
from __future__ import annotations

import asyncio
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
