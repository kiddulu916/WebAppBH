"""Subdomain takeover checker — WSTG-CONF-10."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf10")

_SECTION_ID = "WSTG-CONF-10"

_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "blog", "dev", "staging", "test", "api",
    "app", "admin", "cdn", "static", "assets", "docs", "support",
    "help", "status", "portal", "shop", "store", "news", "media",
    "images", "img", "video", "files", "download", "upload",
    "auth", "login", "dashboard", "panel", "secure", "vpn",
    "remote", "beta", "alpha", "demo", "preview", "sandbox",
    "lab", "labs", "old", "legacy", "archive", "m", "mobile",
    "api2", "api3", "v1", "v2", "internal", "intranet",
    "extranet", "corp", "office", "hr", "finance", "billing",
    "payment", "checkout", "cart", "account", "accounts",
    "client", "clients", "partner", "partners", "crm",
    "wiki", "kb", "forum", "community", "chat",
    "email", "webmail", "mx", "smtp", "calendar",
    "meet", "conference", "stream", "live", "play",
    "games", "search", "analytics", "tracking", "pixel",
    "ad", "ads", "affiliate", "promo", "events", "marketing",
    "site", "web", "home", "landing", "lp", "campaign",
    "cloud", "ci", "cd", "jenkins", "git", "gitlab",
    "grafana", "kibana", "prometheus", "monitor", "monitoring",
    "metrics", "logs", "backup", "db", "database",
    "cache", "proxy", "gateway", "lb",
    "staging2", "dev2", "test2", "qa", "uat", "prod",
    "production", "release", "rc", "hotfix",
    "newsletter", "rss", "feed", "jobs", "careers",
    "press", "ir", "legal", "privacy", "terms", "about",
    "contact", "info", "data", "cdn2", "assets2",
]


def _build_subdomain_list(db_assets: list[str], target_domain: str) -> list[str]:
    """Build a deduplicated list of subdomains to check.

    Sources: DB asset values (stripped to bare hostnames) + common-prefix wordlist.
    Only keeps hostnames that are equal to or a subdomain of target_domain.
    """
    seen: set[str] = set()
    result: list[str] = []

    def _add(host: str) -> None:
        host = host.lower().strip().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            result.append(host)

    for raw in db_assets:
        try:
            if "://" in raw:
                host = urlparse(raw).netloc
            else:
                host = raw.split("/")[0].split("?")[0]
            host = host.split(":")[0].lower().strip()
            if host == target_domain or host.endswith(f".{target_domain}"):
                _add(host)
        except Exception:
            pass

    _add(target_domain)

    for prefix in _COMMON_SUBDOMAINS:
        _add(f"{prefix}.{target_domain}")

    return result


def _parse_subjack_output(text: str) -> list[dict]:
    """Parse subjack JSON array output into a list of result dicts.

    Each dict has keys: subdomain (str), service (str), vulnerable (bool).
    Returns [] on empty input or JSON parse failure.
    """
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if not isinstance(data, list):
            return []
        results = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            results.append({
                "subdomain": entry.get("subdomain", ""),
                "service": entry.get("service", "unknown"),
                "vulnerable": bool(entry.get("vulnerable", False)),
            })
        return results
    except (json.JSONDecodeError, ValueError):
        return []


def _classify_subjack_result(entry: dict) -> dict:
    """Convert a parsed subjack entry to a vulnerability finding dict."""
    subdomain = entry["subdomain"]
    service = entry["service"]

    if entry["vulnerable"]:
        severity = "critical"
        name = f"Subdomain takeover confirmed: {subdomain} via {service}"
        description = (
            f"The subdomain {subdomain} has a dangling CNAME pointing to {service}. "
            f"The resource is unclaimed and can be registered by an attacker to serve "
            f"arbitrary content, enabling phishing, credential harvesting, or cookie theft."
        )
    else:
        severity = "high"
        name = f"Potential subdomain takeover: {subdomain} via {service}"
        description = (
            f"The subdomain {subdomain} has a CNAME chain pointing to {service} "
            f"that could not be confirmed as active. This may be a dangling DNS record "
            f"susceptible to subdomain takeover."
        )

    return {
        "vulnerability": {
            "name": name,
            "severity": severity,
            "description": description,
            "location": subdomain,
            "section_id": _SECTION_ID,
        }
    }


def _parse_nuclei_output(text: str) -> list[dict]:
    """Parse nuclei JSONL output (one JSON object per line) into result dicts.

    Each dict has keys: template_id (str), host (str), matched_at (str),
    severity (str), name (str).
    Malformed lines are silently skipped. Returns [] on empty input.
    """
    text = text.strip()
    if not text:
        return []
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                continue
            # nuclei v2 uses "templateID", nuclei v3 uses "template-id"
            template_id = entry.get("templateID") or entry.get("template-id", "")
            info = entry.get("info", {}) if isinstance(entry.get("info"), dict) else {}
            results.append({
                "template_id": template_id,
                "host": entry.get("host", ""),
                "matched_at": entry.get("matched-at", ""),
                "severity": info.get("severity", "unknown"),
                "name": info.get("name", ""),
            })
        except (json.JSONDecodeError, ValueError):
            continue
    return results


def _classify_nuclei_result(entry: dict) -> dict:
    """Convert a parsed nuclei entry to a vulnerability finding dict.

    nuclei severity "high" or "critical" → confirmed takeover (critical).
    Any other severity → potential takeover (high).
    """
    host = entry["host"]
    matched_at = entry["matched_at"]
    name = entry["name"]
    raw_severity = entry.get("severity", "unknown").lower()

    if raw_severity in ("critical", "high"):
        severity = "critical"
        vuln_name = f"Subdomain takeover confirmed: {host} ({name})"
        description = (
            f"Nuclei confirmed a subdomain takeover vulnerability at {matched_at}. "
            f"Template: {entry['template_id']}. The subdomain {host} is serving "
            f"takeover-indicative content and can be claimed by an attacker."
        )
    else:
        severity = "high"
        vuln_name = f"Potential subdomain takeover: {host} ({name})"
        description = (
            f"Nuclei detected a potential subdomain takeover at {matched_at}. "
            f"Template: {entry['template_id']}. The subdomain {host} may be "
            f"susceptible to takeover based on HTTP response fingerprinting."
        )

    return {
        "vulnerability": {
            "name": vuln_name,
            "severity": severity,
            "description": description,
            "location": matched_at,
            "section_id": _SECTION_ID,
        }
    }


class SubdomainTakeoverChecker(ConfigMgmtTool):
    """Check for subdomain takeover vulnerabilities — WSTG-CONF-10."""

    name = "subdomain_takeover_checker"

    def build_command(self, target, headers=None):
        raise NotImplementedError("SubdomainTakeoverChecker uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("SubdomainTakeoverChecker uses execute() directly")
