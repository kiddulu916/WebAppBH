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


_NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "critical",   # confirmed HTTP fingerprint match = confirmed takeover
    "medium": "high",
    "low": "medium",
    "info": "medium",
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
    """Convert a parsed nuclei entry to a vulnerability finding dict."""
    host = entry["host"]
    matched_at = entry["matched_at"]
    name = entry["name"] or entry["template_id"]
    severity = _NUCLEI_SEVERITY_MAP.get(entry["severity"].lower(), "medium")

    return {
        "vulnerability": {
            "name": f"Subdomain takeover detected: {name} at {host}",
            "severity": severity,
            "description": (
                f"Nuclei template '{entry['template_id']}' matched at {matched_at}. "
                f"The subdomain {host} is vulnerable to takeover by an attacker who "
                f"can claim the backing service."
            ),
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

            raw = target.target_value if hasattr(target, "target_value") else str(target)
            if "://" not in raw:
                raw = f"https://{raw}"
            parsed = urlparse(raw)
            target_domain = (parsed.netloc or parsed.path).split(":")[0].lower()

            if not scope_manager.is_in_scope(raw).in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # Phase 1 — assemble subdomain list
            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["subdomain", "url", "domain", "ip"]),
                )
                db_assets = [
                    a.asset_value
                    for a in (await session.execute(stmt)).scalars().all()
                ]

            subdomains = _build_subdomain_list(db_assets, target_domain)
            if not subdomains:
                log.info(f"{self.name}: no subdomains to check")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            log.info(f"{self.name}: checking {len(subdomains)} subdomains")
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 20,
                "message": f"{self.name}: checking {len(subdomains)} subdomains",
            })

            all_findings: list[dict] = []
            suspects: list[str] = []

            tmp_domains = tmp_subjack = tmp_suspects = None
            try:
                # Write full subdomain list to temp file
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", prefix="st_domains_", delete=False
                ) as f:
                    f.write("\n".join(subdomains))
                    tmp_domains = f.name

                # Phase 2 — subjack
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", prefix="st_subjack_", delete=False
                ) as f:
                    tmp_subjack = f.name

                try:
                    await self.run_subprocess([
                        "subjack", "-w", tmp_domains, "-o", tmp_subjack,
                        "-t", "20", "-ssl", "-a", "-c", "/fingerprints.json",
                    ])
                except FileNotFoundError:
                    log.warning(f"{self.name}: subjack binary not found, skipping Phase 2")
                except asyncio.TimeoutError:
                    log.warning(f"{self.name}: subjack timed out, skipping Phase 2")
                else:
                    if os.path.exists(tmp_subjack):
                        with open(tmp_subjack) as f:
                            subjack_text = f.read()
                        for entry in _parse_subjack_output(subjack_text):
                            all_findings.append(_classify_subjack_result(entry))
                            suspects.append(entry["subdomain"])

                log.info(f"{self.name}: {len(suspects)} suspects from subjack")
                await push_task(f"events:{target_id}", {
                    "event": "TOOL_PROGRESS", "container": container_name,
                    "tool": self.name, "progress": 60,
                    "message": (
                        f"{self.name}: {len(suspects)} suspects found, running nuclei"
                    ),
                })

                # Phase 3 — nuclei (suspects only)
                if suspects:
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".txt", prefix="st_suspects_", delete=False
                    ) as f:
                        f.write("\n".join(suspects))
                        tmp_suspects = f.name

                    try:
                        nuclei_stdout = await self.run_subprocess([
                            "nuclei", "-l", tmp_suspects,
                            "-t", "/nuclei-templates/custom/",
                            "-t", "/nuclei-templates/community/http/takeovers/",
                            "-json",
                            "-silent",
                        ])
                        for entry in _parse_nuclei_output(nuclei_stdout):
                            all_findings.append(_classify_nuclei_result(entry))
                    except FileNotFoundError:
                        log.warning(f"{self.name}: nuclei binary not found, skipping Phase 3")
                    except asyncio.TimeoutError:
                        log.warning(f"{self.name}: nuclei timed out, skipping Phase 3")

            finally:
                for tmp in (tmp_domains, tmp_subjack, tmp_suspects):
                    if tmp and os.path.exists(tmp):
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass

            # Deduplicate by (location, name)
            seen_keys: set[tuple] = set()
            unique_findings: list[dict] = []
            for finding in all_findings:
                if "vulnerability" in finding:
                    v = finding["vulnerability"]
                    key = (v.get("location", ""), v.get("name", ""))
                    if key not in seen_keys:
                        seen_keys.add(key)
                        unique_findings.append(finding)

            found = len(unique_findings)
            new_count = in_scope_count = 0
            for item in unique_findings:
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
