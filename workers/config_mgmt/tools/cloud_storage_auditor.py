"""Cloud storage configuration auditor — WSTG-CONF-11."""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse
from xml.etree import ElementTree

import aiohttp

from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf11")

_SECTION_ID = "WSTG-CONF-11"

# ── Compiled regex patterns ───────────────────────────────────────────────────

_S3_PATTERNS = [
    # Virtual-hosted: bucket.s3[-region].amazonaws.com
    re.compile(
        r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][\w\-]+)?\.amazonaws\.com",
        re.IGNORECASE,
    ),
    # Path-style: s3[-region].amazonaws.com/bucket
    re.compile(
        r"s3(?:[.\-][\w\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])",
        re.IGNORECASE,
    ),
    # Website endpoint: bucket.s3-website[-.]region.amazonaws.com
    re.compile(
        r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-website[-\.][\w\-]+\.amazonaws\.com",
        re.IGNORECASE,
    ),
]

_AZURE_PATTERNS = [
    # account.{blob|file|queue|table}.core.windows.net[/container]
    re.compile(
        r"([a-z0-9][a-z0-9\-]{1,22}[a-z0-9])"
        r"\.(?:blob|file|queue|table)\.core\.windows\.net"
        r"(?:/([a-z0-9][a-z0-9\-]{0,62}))?",
        re.IGNORECASE,
    ),
]

_GCS_PATTERNS = [
    # bucket.storage.googleapis.com
    re.compile(
        r"([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])\.storage\.googleapis\.com",
        re.IGNORECASE,
    ),
    # storage.googleapis.com/bucket  OR  storage.cloud.google.com/bucket
    re.compile(
        r"storage\.(?:googleapis\.com|cloud\.google\.com)"
        r"/([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])",
        re.IGNORECASE,
    ),
]


# ── Extraction ────────────────────────────────────────────────────────────────

def _extract_storage_refs(body: str, provider: str) -> list[str]:
    """Return all raw matched strings for the given provider found in body.

    provider must be one of: "s3", "azure", "gcs".
    Returns full match strings (group 0) — normalization is a separate step.
    """
    patterns = {"s3": _S3_PATTERNS, "azure": _AZURE_PATTERNS, "gcs": _GCS_PATTERNS}.get(
        provider, []
    )
    results: list[str] = []
    for pat in patterns:
        for m in pat.finditer(body):
            results.append(m.group(0))
    return results


# ── Normalization ─────────────────────────────────────────────────────────────

def _normalize_s3_ref(raw: str) -> tuple[str, str | None] | None:
    """Parse a raw S3 match string into (bucket_name, region | None).

    Returns None if raw does not match any known S3 URL format.
    """
    raw = raw.lower().strip()
    # Virtual-hosted, no region: bucket.s3.amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), None
    # Virtual-hosted, with region: bucket.s3[-.]region.amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-]([\w\-]+)\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), m.group(2)
    # Path-style: s3[-.]region.amazonaws.com/bucket or s3.amazonaws.com/bucket
    m = re.match(
        r"^s3(?:[.\-]([\w\-]+))?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])$",
        raw,
    )
    if m:
        return m.group(2), m.group(1)
    # Website endpoint: bucket.s3-website[-.]region.amazonaws.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-website[-\.][\w\-]+\.amazonaws\.com$",
        raw,
    )
    if m:
        return m.group(1), None
    return None


def _normalize_azure_ref(raw: str) -> tuple[str, str | None] | None:
    """Parse a raw Azure match string into (account, container | None).

    Returns None if raw does not match any known Azure storage URL format.
    """
    raw = raw.lower().strip()
    m = re.match(
        r"^([a-z0-9][a-z0-9\-]{1,22}[a-z0-9])"
        r"\.(?:blob|file|queue|table)\.core\.windows\.net"
        r"(?:/([a-z0-9][a-z0-9\-]{0,62}))?$",
        raw,
    )
    if m:
        return m.group(1), m.group(2) or None
    return None


def _normalize_gcs_ref(raw: str) -> str | None:
    """Parse a raw GCS match string into a bucket name.

    Returns None if raw does not match any known GCS URL format.
    """
    raw = raw.lower().strip()
    # bucket.storage.googleapis.com
    m = re.match(
        r"^([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])\.storage\.googleapis\.com$", raw
    )
    if m:
        return m.group(1)
    # storage.googleapis.com/bucket  OR  storage.cloud.google.com/bucket
    m = re.match(
        r"^storage\.(?:googleapis\.com|cloud\.google\.com)"
        r"/([a-z0-9][a-z0-9.\-_]{1,220}[a-z0-9])$",
        raw,
    )
    if m:
        return m.group(1)
    return None


# ── s3scanner ─────────────────────────────────────────────────────────────────

def _parse_s3scanner_output(text: str) -> list[dict]:
    """Parse s3scanner JSON file output into a list of normalised result dicts.

    Handles both s3scanner v1 ('bucket' key) and v2 ('name' key) field names.
    Returns [] on empty input or JSON parse failure.
    """
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        entries = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        results = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            results.append({
                "bucket": (entry["name"] if entry.get("name") else entry.get("bucket", "")),
                "exists": bool(entry.get("exists", False)),
                "listable": bool(
                    entry.get("objects_listable", entry.get("listable", False))
                ),
                "readable": bool(
                    entry.get("objects_readable", entry.get("readable", False))
                ),
                "writable": bool(
                    entry.get("objects_writable", entry.get("writable", False))
                ),
            })
        return results
    except (json.JSONDecodeError, ValueError):
        return []


def _classify_s3scanner_result(entry: dict) -> dict | None:
    """Convert one parsed s3scanner entry into a vulnerability or observation dict.

    Returns None only when the entry has no useful signal (malformed).
    """
    bucket = entry.get("bucket", "")
    location = f"https://{bucket}.s3.amazonaws.com"

    if not entry.get("exists"):
        return {
            "observation": {
                "type": "cloud_storage",
                "value": f"s3_bucket_not_found: {bucket}",
                "details": {
                    "provider": "aws_s3",
                    "bucket": bucket,
                    "note": "Bucket does not exist — potential unclaimed resource",
                },
            }
        }

    if entry.get("writable"):
        return {
            "vulnerability": {
                "name": f"Publicly writable S3 bucket: {bucket}",
                "severity": "critical",
                "description": (
                    f"S3 bucket '{bucket}' allows anonymous write access. "
                    f"An attacker can upload arbitrary files to serve malicious content "
                    f"or exfiltrate data."
                ),
                "location": location,
                "section_id": _SECTION_ID,
            }
        }

    if entry.get("listable"):
        return {
            "vulnerability": {
                "name": f"Publicly listable S3 bucket: {bucket}",
                "severity": "high",
                "description": (
                    f"S3 bucket '{bucket}' allows anonymous listing of its contents. "
                    f"Sensitive files may be enumerated and downloaded."
                ),
                "location": location,
                "section_id": _SECTION_ID,
            }
        }

    if entry.get("readable"):
        return {
            "vulnerability": {
                "name": f"Publicly readable S3 bucket: {bucket}",
                "severity": "medium",
                "description": (
                    f"S3 bucket '{bucket}' allows anonymous read access to individual "
                    f"objects but does not expose a directory listing."
                ),
                "location": location,
                "section_id": _SECTION_ID,
            }
        }

    # Exists but fully restricted
    return {
        "observation": {
            "type": "cloud_storage",
            "value": f"s3_bucket_restricted: {bucket}",
            "details": {
                "provider": "aws_s3",
                "bucket": bucket,
                "note": "Bucket exists but access is fully restricted",
            },
        }
    }


# ── cloud storage enumeration ─────────────────────────────────────────────────

_CLOUD_SUFFIXES = [
    "", "-dev", "-prod", "-staging", "-backup", "-test", "-qa",
    "-data", "-logs", "-assets", "-static", "-media", "-cdn",
    "-uploads", "-storage", "-files", "-public", "-private",
    "-www", "-api", "-app", "-web", "-img", "-images",
]

_BUCKET_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$')


def _generate_cloud_candidates(domain: str, org: str) -> set[str]:
    """Generate bucket/storage-account name candidates from domain and org keywords."""
    bases = {
        org.lower(),
        domain.lower(),
        domain.lower().replace(".", "-"),
        domain.lower().replace(".", ""),
    }
    candidates: set[str] = set()
    for base in bases:
        for suffix in _CLOUD_SUFFIXES:
            name = base + suffix
            # AWS S3 bucket name rules: 3–63 chars, lowercase alphanumeric + hyphens
            if 3 <= len(name) <= 63 and _BUCKET_NAME_RE.match(name):
                candidates.add(name)
    return candidates


def _parse_nuclei_cloud_output(text: str) -> list[str]:
    """Parse nuclei JSONL output and return matched-at URLs."""
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if isinstance(entry, dict):
                # nuclei v2 uses "matched-at"; v3 keeps the same key
                matched_at = entry.get("matched-at", "")
                if matched_at:
                    urls.append(matched_at)
        except (json.JSONDecodeError, KeyError):
            pass
    return urls


# ── azcopy / Azure ────────────────────────────────────────────────────────────

def _parse_azcopy_output(text: str) -> list[dict]:
    """Parse azcopy list stdout into [{container_url: str, accessible: bool}].

    azcopy v10 prefixes each listed object with 'INFO:'.
    Error responses contain 'RESPONSE Status: 4xx' or known failure keywords.
    Empty input is treated as inaccessible (no output = command failed or no access).
    """
    text = text.strip()
    if not text:
        return [{"container_url": "", "accessible": False}]
    error_markers = [
        "RESPONSE Status: 4",
        "RESPONSE Status: 5",
        "AuthorizationFailure",
        "failed to authenticate",
        "does not exist",
        "ResourceNotFound",
    ]
    has_error = any(marker in text for marker in error_markers)
    return [{"container_url": "", "accessible": not has_error}]


def _classify_azure_probe(
    container_url: str,
    list_accessible: bool,
    head_readable: bool,
    write_status: int,
) -> dict | None:
    """Classify an Azure Blob container probe result into a finding dict.

    Priority order: write > list > read > None (fully restricted).
    Returns None when the container appears fully restricted.
    """
    if write_status in (200, 201):
        access = "write and list" if list_accessible else "write"
        return {
            "vulnerability": {
                "name": f"Publicly writable Azure Blob container: {container_url}",
                "severity": "critical",
                "description": (
                    f"Azure Blob container at {container_url} allows anonymous {access} "
                    f"access. An attacker can upload arbitrary files."
                ),
                "location": container_url,
                "section_id": _SECTION_ID,
            }
        }

    if list_accessible:
        return {
            "vulnerability": {
                "name": f"Publicly listable Azure Blob container: {container_url}",
                "severity": "high",
                "description": (
                    f"Azure Blob container at {container_url} allows anonymous listing "
                    f"of its contents."
                ),
                "location": container_url,
                "section_id": _SECTION_ID,
            }
        }

    if head_readable:
        return {
            "vulnerability": {
                "name": f"Publicly readable Azure Blob container: {container_url}",
                "severity": "medium",
                "description": (
                    f"Azure Blob container at {container_url} allows anonymous read "
                    f"access to individual objects but does not expose a directory listing."
                ),
                "location": container_url,
                "section_id": _SECTION_ID,
            }
        }

    return None


# ── GCS ───────────────────────────────────────────────────────────────────────

def _classify_gcs_probe(
    bucket_url: str,
    list_body: str,
    write_status: int,
) -> dict | None:
    """Classify a GCS bucket probe result into a finding dict.

    list_body is the raw HTTP response body from GET /?prefix=.
    Priority order: write > list > None.
    """
    is_listable = "ListBucketResult" in list_body or "<Contents>" in list_body

    if write_status in (200, 201):
        access = "write and list" if is_listable else "write"
        return {
            "vulnerability": {
                "name": f"Publicly writable GCS bucket: {bucket_url}",
                "severity": "critical",
                "description": (
                    f"GCS bucket at {bucket_url} allows anonymous {access} access. "
                    f"An attacker can upload arbitrary files."
                ),
                "location": bucket_url,
                "section_id": _SECTION_ID,
            }
        }

    if is_listable:
        return {
            "vulnerability": {
                "name": f"Publicly listable GCS bucket: {bucket_url}",
                "severity": "high",
                "description": (
                    f"GCS bucket at {bucket_url} allows anonymous listing of its contents."
                ),
                "location": bucket_url,
                "section_id": _SECTION_ID,
            }
        }

    return None


# ── Generic write probe ───────────────────────────────────────────────────────

def _classify_write_probe(url: str, provider: str, put_status: int) -> dict | None:
    """Classify a raw write probe (PUT) result.

    Used when the caller issues a PUT independently of the provider-specific
    scan flow. Returns None for any status other than 200 or 201.
    """
    if put_status in (200, 201):
        return {
            "vulnerability": {
                "name": f"Publicly writable {provider.upper()} storage: {url}",
                "severity": "critical",
                "description": (
                    f"The {provider} storage resource at {url} allows anonymous write "
                    f"access (HTTP PUT returned {put_status}). "
                    f"An attacker can upload arbitrary content."
                ),
                "location": url,
                "section_id": _SECTION_ID,
            }
        }
    return None


class CloudStorageAuditor(ConfigMgmtTool):
    """Audit cloud storage configurations — WSTG-CONF-11."""

    name = "cloud_storage_auditor"

    def build_command(self, target, headers=None):
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("CloudStorageAuditor uses execute() directly")

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
            parsed_url = urlparse(raw)
            target_domain = (parsed_url.netloc or parsed_url.path).split(":")[0].lower()
            org_name = target_domain.split(".")[0]
            base_url = raw.rstrip("/")

            if not scope_manager.is_in_scope(raw).in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # ── Phase 1: Extract ───────────────────────────────────────────
            s3_buckets: set[str] = set()
            azure_refs: set[tuple[str, str | None]] = set()
            gcs_buckets: set[str] = set()

            def _ingest(body: str) -> None:
                for raw_ref in _extract_storage_refs(body, "s3"):
                    r = _normalize_s3_ref(raw_ref)
                    if r:
                        s3_buckets.add(r[0])
                for raw_ref in _extract_storage_refs(body, "azure"):
                    r = _normalize_azure_ref(raw_ref)
                    if r:
                        azure_refs.add(r)
                for raw_ref in _extract_storage_refs(body, "gcs"):
                    r = _normalize_gcs_ref(raw_ref)
                    if r:
                        gcs_buckets.add(r)

            # Source A: DB assets
            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["url", "subdomain", "domain", "cloud_storage"]),
                )
                db_assets = [
                    a.asset_value
                    for a in (await session.execute(stmt)).scalars().all()
                ]
            for val in db_assets:
                _ingest(val)

            # Source B: Live crawl
            crawl_urls = [
                base_url,
                f"{base_url}/robots.txt",
                f"{base_url}/sitemap.xml",
                f"{base_url}/static/js/",
                f"{base_url}/assets/js/",
                f"{base_url}/js/",
            ]
            http_timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=http_timeout) as http:
                async def _fetch(url: str) -> str:
                    try:
                        async with http.get(url, ssl=False) as resp:
                            return await resp.text(errors="replace")
                    except Exception:
                        return ""

                bodies = await asyncio.gather(*[_fetch(u) for u in crawl_urls])
            for body in bodies:
                _ingest(body)

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 20,
                "message": (
                    f"{self.name}: extracted {len(s3_buckets)} S3, "
                    f"{len(azure_refs)} Azure, {len(gcs_buckets)} GCS refs"
                ),
            })

            # ── Phase 2: Enumerate (nuclei cloud/misconfiguration templates) ──
            # Generate candidate names, build provider URLs, probe with nuclei.
            candidates = _generate_cloud_candidates(target_domain, org_name)
            enum_urls: list[str] = []
            for name in sorted(candidates):
                enum_urls.append(f"https://{name}.s3.amazonaws.com")
                enum_urls.append(f"https://{name}.blob.core.windows.net")
                enum_urls.append(f"https://storage.googleapis.com/{name}")

            tmp_enum = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", prefix="csa_enum_", delete=False
                ) as f:
                    f.write("\n".join(enum_urls))
                    tmp_enum = f.name

                try:
                    nuclei_stdout = await self.run_subprocess([
                        "nuclei", "-l", tmp_enum,
                        "-t", "/nuclei-templates/community/cloud/",
                        "-t", "/nuclei-templates/community/misconfiguration/",
                        "-json", "-silent", "-no-color",
                        "-etags", "intrusive",
                    ])
                    for matched_url in _parse_nuclei_cloud_output(nuclei_stdout):
                        raw_host = (
                            matched_url
                            .replace("https://", "")
                            .replace("http://", "")
                            .strip("/")
                        )
                        r_s3 = _normalize_s3_ref(raw_host)
                        if r_s3:
                            s3_buckets.add(r_s3[0])
                            continue
                        r_az = _normalize_azure_ref(raw_host)
                        if r_az:
                            azure_refs.add(r_az)
                            continue
                        r_gcs = _normalize_gcs_ref(raw_host)
                        if r_gcs:
                            gcs_buckets.add(r_gcs)
                except FileNotFoundError:
                    log.warning(f"{self.name}: nuclei not found, skipping Phase 2")
                except asyncio.TimeoutError:
                    log.warning(f"{self.name}: nuclei timed out, skipping Phase 2")
            finally:
                if tmp_enum and os.path.exists(tmp_enum):
                    try:
                        os.unlink(tmp_enum)
                    except OSError:
                        pass

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 35,
                "message": (
                    f"{self.name}: after enum — {len(s3_buckets)} S3, "
                    f"{len(azure_refs)} Azure, {len(gcs_buckets)} GCS"
                ),
            })

            if not s3_buckets and not azure_refs and not gcs_buckets:
                log.info(f"{self.name}: no cloud storage refs found, nothing to probe")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            all_findings: list[dict] = []

            # ── Phase 3: S3 Scan (s3scanner) ──────────────────────────────
            tmp_s3_in = tmp_s3_out = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", prefix="csa_s3_", delete=False
                ) as f:
                    f.write("\n".join(s3_buckets))
                    tmp_s3_in = f.name

                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", prefix="csa_s3out_", delete=False
                ) as f:
                    tmp_s3_out = f.name

                try:
                    await self.run_subprocess([
                        "s3scanner", "scan",
                        "--bucket-file", tmp_s3_in,
                        "--json-output", tmp_s3_out,
                    ])
                except FileNotFoundError:
                    log.warning(f"{self.name}: s3scanner not found, skipping Phase 3")
                except asyncio.TimeoutError:
                    log.warning(f"{self.name}: s3scanner timed out, skipping Phase 3")
                else:
                    if os.path.exists(tmp_s3_out):
                        with open(tmp_s3_out) as fh:
                            for entry in _parse_s3scanner_output(fh.read()):
                                finding = _classify_s3scanner_result(entry)
                                if finding:
                                    all_findings.append(finding)
            finally:
                for tmp in (tmp_s3_in, tmp_s3_out):
                    if tmp and os.path.exists(tmp):
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 55,
                "message": f"{self.name}: S3 scan done — {len(all_findings)} findings",
            })

            # ── Phase 4: Azure Scan (azcopy + aiohttp) ────────────────────
            probe_ts = int(time.time())
            probe_filename = f"bbh-probe-{probe_ts}.txt"

            # Expand (account, None) by enumerating containers via the XML API
            expanded_azure: set[tuple[str, str]] = set()
            probe_timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=probe_timeout) as http:
                for account, container in list(azure_refs):
                    if container is None:
                        try:
                            enum_url = (
                                f"https://{account}.blob.core.windows.net/?comp=list"
                            )
                            async with http.get(enum_url, ssl=False) as resp:
                                if resp.status == 200:
                                    body = await resp.text(errors="replace")
                                    try:
                                        root = ElementTree.fromstring(body)
                                        for name_el in root.iter("Name"):
                                            if name_el.text:
                                                expanded_azure.add(
                                                    (account, name_el.text)
                                                )
                                    except ElementTree.ParseError:
                                        pass
                        except Exception:
                            pass
                    else:
                        expanded_azure.add((account, container))

            azcopy_available = True
            async with aiohttp.ClientSession(timeout=probe_timeout) as http:
                for account, container in expanded_azure:
                    c_url = (
                        f"https://{account}.blob.core.windows.net/{container}"
                    )
                    list_accessible = False
                    head_readable = False
                    write_status = 0

                    if azcopy_available:
                        try:
                            azcopy_out = await self.run_subprocess(
                                ["azcopy", "list", c_url]
                            )
                            results = _parse_azcopy_output(azcopy_out)
                            if results:
                                list_accessible = results[0]["accessible"]
                        except FileNotFoundError:
                            log.warning(
                                f"{self.name}: azcopy not found, skipping all azcopy checks"
                            )
                            azcopy_available = False
                        except asyncio.TimeoutError:
                            log.warning(
                                f"{self.name}: azcopy timed out for {c_url}"
                            )

                    if not list_accessible:
                        try:
                            async with http.head(
                                f"{c_url}/index.html", ssl=False
                            ) as resp:
                                head_readable = resp.status == 200
                        except Exception:
                            pass

                    if list_accessible or head_readable:
                        try:
                            async with http.put(
                                f"{c_url}/{probe_filename}",
                                data=b"bbh",
                                ssl=False,
                            ) as resp:
                                write_status = resp.status
                                if write_status in (200, 201):
                                    try:
                                        async with http.delete(
                                            f"{c_url}/{probe_filename}", ssl=False
                                        ):
                                            pass
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                    finding = _classify_azure_probe(
                        c_url, list_accessible, head_readable, write_status
                    )
                    if finding:
                        all_findings.append(finding)

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 70,
                "message": f"{self.name}: Azure scan done — {len(all_findings)} findings",
            })

            # ── Phase 5: GCS Scan (aiohttp) ───────────────────────────────
            async with aiohttp.ClientSession(timeout=probe_timeout) as http:
                for bucket in gcs_buckets:
                    b_url = f"https://storage.googleapis.com/{bucket}"
                    list_body = ""
                    write_status = 0

                    try:
                        async with http.get(
                            f"{b_url}/?prefix=", ssl=False
                        ) as resp:
                            if resp.status == 200:
                                list_body = await resp.text(errors="replace")
                    except Exception:
                        pass

                    # Always attempt write probe — detect write-only misconfigurations
                    try:
                        async with http.put(
                            f"{b_url}/{probe_filename}",
                            data=b"bbh",
                            ssl=False,
                        ) as resp:
                            write_status = resp.status
                            if write_status in (200, 201):
                                try:
                                    async with http.delete(
                                        f"{b_url}/{probe_filename}", ssl=False
                                    ):
                                        pass
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    finding = _classify_gcs_probe(b_url, list_body, write_status)
                    if finding:
                        all_findings.append(finding)

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 85,
                "message": f"{self.name}: GCS scan done — {len(all_findings)} findings",
            })

            # ── Persist ────────────────────────────────────────────────────
            seen_keys: set[tuple] = set()
            unique_findings: list[dict] = []
            for finding in all_findings:
                if "vulnerability" in finding:
                    v = finding["vulnerability"]
                    key = (v.get("location", ""), v.get("name", ""))
                elif "observation" in finding:
                    o = finding["observation"]
                    key = (o.get("type", ""), o.get("value", ""))
                else:
                    continue
                if key not in seen_keys:
                    seen_keys.add(key)
                    unique_findings.append(finding)

            found = len(unique_findings)
            new_count = in_scope_count = 0
            for item in unique_findings:
                inserted = await self._process_result(
                    item, scope_manager, target_id, log
                )
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
