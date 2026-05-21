# WSTG-CONF-10 Subdomain Takeover Tester Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `SubdomainTakeoverChecker` as a production-quality async tool that runs subjack (CNAME fingerprinting) then nuclei (HTTP verification) against assembled subdomains, storing confirmed and potential takeovers as `Vulnerability` rows tagged `WSTG-CONF-10`.

**Architecture:** Phase 1 assembles subdomains from DB assets plus a common-prefix wordlist. Phase 2 runs subjack against all subdomains for fast CNAME triage. Phase 3 runs nuclei against only the subjack suspects, using curated custom templates plus community takeover templates. All detection logic lives in pure module-level functions so unit tests need no mocks or DB.

**Tech Stack:** Python 3.10, asyncio, httpx (not used directly — tool shells out), sqlalchemy async, subjack (Go), nuclei (Go), NDJSON parsing, pytest.

---

## File Map

| Action | Path |
|--------|------|
| Create (directory) | `workers/config_mgmt/nuclei-templates/` |
| Rewrite | `workers/config_mgmt/tools/subdomain_takeover_checker.py` |
| Modify | `docker/Dockerfile.config_mgmt` |
| Create | `tests/unit/config_mgmt/test_subdomain_takeover_checker.py` |

**No changes needed to:** `pipeline.py`, `playbooks.py`, `worker-stages.ts`, `concurrency.py`, `tools/__init__.py` — all three coherence layers are already wired correctly.

---

## Task 1: Copy curated nuclei templates into the project

**Files:**
- Create: `workers/config_mgmt/nuclei-templates/` (directory of YAML files)

- [ ] **Step 1: Create the templates directory and copy**

```powershell
New-Item -ItemType Directory -Force "workers\config_mgmt\nuclei-templates"
Copy-Item "C:\Users\dat1k\Projects\Custom-Nuclei-Templates\takeovers\*" `
          "workers\config_mgmt\nuclei-templates\" -Recurse
```

- [ ] **Step 2: Verify the copy**

```powershell
(Get-ChildItem "workers\config_mgmt\nuclei-templates\*.yaml").Count
```

Expected: a count greater than 50.

- [ ] **Step 3: Commit**

```powershell
git add workers/config_mgmt/nuclei-templates/
git commit -m "feat(conf10): add curated nuclei subdomain takeover templates"
```

---

## Task 2: Write all unit tests (TDD red phase)

**Files:**
- Create: `tests/unit/config_mgmt/test_subdomain_takeover_checker.py`

- [ ] **Step 1: Write the test file**

```python
"""Unit tests for SubdomainTakeoverChecker pure helpers (WSTG-CONF-10)."""
from workers.config_mgmt.tools.subdomain_takeover_checker import (
    _SECTION_ID,
    _build_subdomain_list,
    _parse_subjack_output,
    _classify_subjack_result,
    _parse_nuclei_output,
    _classify_nuclei_result,
)


# ── _build_subdomain_list ────────────────────────────────────────────────────

def test_build_subdomain_list_includes_wordlist():
    result = _build_subdomain_list([], "example.com")
    assert "www.example.com" in result
    assert "api.example.com" in result


def test_build_subdomain_list_includes_target_domain():
    result = _build_subdomain_list([], "example.com")
    assert "example.com" in result


def test_build_subdomain_list_strips_schemes():
    assets = ["https://api.example.com/v1/users?q=1"]
    result = _build_subdomain_list(assets, "example.com")
    assert "api.example.com" in result
    assert "https://api.example.com/v1/users?q=1" not in result


def test_build_subdomain_list_filters_out_of_scope():
    assets = ["https://other.com", "https://sub.example.com"]
    result = _build_subdomain_list(assets, "example.com")
    assert "other.com" not in result
    assert "sub.example.com" in result


def test_build_subdomain_list_deduplicates():
    # www.example.com comes from both DB and wordlist
    assets = ["https://www.example.com/page"]
    result = _build_subdomain_list(assets, "example.com")
    assert result.count("www.example.com") == 1


def test_build_subdomain_list_empty_db():
    result = _build_subdomain_list([], "example.com")
    assert len(result) > 0


# ── _parse_subjack_output ────────────────────────────────────────────────────

def test_parse_subjack_empty_string():
    assert _parse_subjack_output("") == []


def test_parse_subjack_empty_array():
    assert _parse_subjack_output("[]") == []


def test_parse_subjack_malformed_json():
    assert _parse_subjack_output("not json at all") == []


def test_parse_subjack_vulnerable_entry():
    raw = '[{"subdomain":"sub.example.com","service":"GitHub","vulnerable":true}]'
    result = _parse_subjack_output(raw)
    assert len(result) == 1
    assert result[0]["subdomain"] == "sub.example.com"
    assert result[0]["service"] == "GitHub"
    assert result[0]["vulnerable"] is True


def test_parse_subjack_non_vulnerable_entry():
    raw = '[{"subdomain":"blog.example.com","service":"Ghost","vulnerable":false}]'
    result = _parse_subjack_output(raw)
    assert len(result) == 1
    assert result[0]["vulnerable"] is False


def test_parse_subjack_multiple_entries():
    raw = '[{"subdomain":"a.example.com","service":"GitHub","vulnerable":true},{"subdomain":"b.example.com","service":"Heroku","vulnerable":false}]'
    result = _parse_subjack_output(raw)
    assert len(result) == 2


# ── _classify_subjack_result ─────────────────────────────────────────────────

def test_classify_subjack_vulnerable_is_critical():
    entry = {"subdomain": "sub.example.com", "service": "GitHub", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_subjack_dangling_is_high():
    entry = {"subdomain": "blog.example.com", "service": "Ghost", "vulnerable": False}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_subjack_section_id():
    entry = {"subdomain": "sub.example.com", "service": "GitHub", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-10"


def test_classify_subjack_has_location():
    entry = {"subdomain": "blog.example.com", "service": "Ghost", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert result["vulnerability"]["location"] == "blog.example.com"


def test_classify_subjack_name_includes_service():
    entry = {"subdomain": "sub.example.com", "service": "GitHub", "vulnerable": True}
    result = _classify_subjack_result(entry)
    assert "GitHub" in result["vulnerability"]["name"]


# ── _parse_nuclei_output ─────────────────────────────────────────────────────

def test_parse_nuclei_empty_output():
    assert _parse_nuclei_output("") == []


def test_parse_nuclei_single_line():
    line = '{"templateID":"github-takeover","host":"sub.example.com","matched-at":"http://sub.example.com","info":{"name":"GitHub Pages Takeover","severity":"high"},"type":"http"}'
    result = _parse_nuclei_output(line)
    assert len(result) == 1
    assert result[0]["template_id"] == "github-takeover"
    assert result[0]["host"] == "sub.example.com"
    assert result[0]["matched_at"] == "http://sub.example.com"
    assert result[0]["severity"] == "high"
    assert result[0]["name"] == "GitHub Pages Takeover"


def test_parse_nuclei_multi_line():
    lines = "\n".join([
        '{"templateID":"github-takeover","host":"a.example.com","matched-at":"http://a.example.com","info":{"name":"GitHub","severity":"high"},"type":"http"}',
        '{"templateID":"heroku-takeover","host":"b.example.com","matched-at":"http://b.example.com","info":{"name":"Heroku","severity":"high"},"type":"http"}',
    ])
    result = _parse_nuclei_output(lines)
    assert len(result) == 2


def test_parse_nuclei_malformed_line_skipped():
    text = "not json\n" + '{"templateID":"github-takeover","host":"sub.example.com","matched-at":"http://sub.example.com","info":{"name":"GitHub","severity":"high"},"type":"http"}'
    result = _parse_nuclei_output(text)
    assert len(result) == 1


def test_parse_nuclei_hyphen_template_id():
    # nuclei v3 uses "template-id" instead of "templateID"
    line = '{"template-id":"github-takeover","host":"sub.example.com","matched-at":"http://sub.example.com","info":{"name":"GitHub","severity":"high"},"type":"http"}'
    result = _parse_nuclei_output(line)
    assert len(result) == 1
    assert result[0]["template_id"] == "github-takeover"


# ── _classify_nuclei_result ──────────────────────────────────────────────────

def test_classify_nuclei_critical_severity():
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "critical", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_nuclei_high_maps_to_critical():
    # nuclei high = confirmed HTTP match = confirmed takeover
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "high", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_nuclei_medium_maps_to_high():
    entry = {"template_id": "some-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "medium", "name": "Some Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_nuclei_section_id():
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com", "severity": "high", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-10"


def test_classify_nuclei_location_is_matched_at():
    entry = {"template_id": "github-takeover", "host": "sub.example.com",
             "matched_at": "http://sub.example.com/", "severity": "high", "name": "GitHub Takeover"}
    result = _classify_nuclei_result(entry)
    assert result["vulnerability"]["location"] == "http://sub.example.com/"


# ── _SECTION_ID constant ─────────────────────────────────────────────────────

def test_section_id_constant():
    assert _SECTION_ID == "WSTG-CONF-10"
```

- [ ] **Step 2: Run tests — confirm they all fail with ImportError**

```powershell
pytest tests/unit/config_mgmt/test_subdomain_takeover_checker.py -v 2>&1 | Select-Object -First 20
```

Expected: `ImportError: cannot import name '_SECTION_ID' from 'workers.config_mgmt.tools.subdomain_takeover_checker'`

- [ ] **Step 3: Commit the test file**

```powershell
git add tests/unit/config_mgmt/test_subdomain_takeover_checker.py
git commit -m "test(conf10): write failing unit tests for subdomain takeover checker"
```

---

## Task 3: Implement constants, subdomain assembly, and subjack parsing

**Files:**
- Modify: `workers/config_mgmt/tools/subdomain_takeover_checker.py`

- [ ] **Step 1: Replace the entire file with the constants and first three functions**

```python
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


class SubdomainTakeoverChecker(ConfigMgmtTool):
    """Check for subdomain takeover vulnerabilities — WSTG-CONF-10."""

    name = "subdomain_takeover_checker"

    def build_command(self, target, headers=None):
        raise NotImplementedError("SubdomainTakeoverChecker uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("SubdomainTakeoverChecker uses execute() directly")
```

- [ ] **Step 2: Run the subdomain and subjack tests — confirm they pass**

```powershell
pytest tests/unit/config_mgmt/test_subdomain_takeover_checker.py -v -k "subdomain or subjack or section_id"
```

Expected: all `test_build_subdomain_list_*`, `test_parse_subjack_*`, `test_classify_subjack_*`, and `test_section_id_constant` tests PASS. The nuclei tests still FAIL with `ImportError`.

- [ ] **Step 3: Commit**

```powershell
git add workers/config_mgmt/tools/subdomain_takeover_checker.py
git commit -m "feat(conf10): implement constants, _build_subdomain_list, and subjack parsers"
```

---

## Task 4: Implement nuclei output parsing

**Files:**
- Modify: `workers/config_mgmt/tools/subdomain_takeover_checker.py`

- [ ] **Step 1: Add the nuclei severity map and two parsing functions**

Insert these two blocks directly after `_classify_subjack_result` and before the `SubdomainTakeoverChecker` class definition.

```python
_NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "critical",   # confirmed HTTP fingerprint match = confirmed takeover
    "medium": "high",
    "low": "medium",
    "info": "medium",
}


def _parse_nuclei_output(text: str) -> list[dict]:
    """Parse nuclei NDJSON output (one JSON object per line).

    Each output dict has keys: template_id, host, matched_at, severity, name.
    Malformed lines are silently skipped.
    """
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            info = obj.get("info", {})
            results.append({
                "template_id": obj.get("templateID") or obj.get("template-id", ""),
                "host": obj.get("host", ""),
                "matched_at": obj.get("matched-at") or obj.get("host", ""),
                "severity": info.get("severity", "info"),
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
```

- [ ] **Step 2: Run all unit tests — confirm they all pass**

```powershell
pytest tests/unit/config_mgmt/test_subdomain_takeover_checker.py -v
```

Expected: all tests PASS, 0 failures.

- [ ] **Step 3: Commit**

```powershell
git add workers/config_mgmt/tools/subdomain_takeover_checker.py
git commit -m "feat(conf10): implement nuclei output parsing functions"
```

---

## Task 5: Implement `SubdomainTakeoverChecker.execute()`

**Files:**
- Modify: `workers/config_mgmt/tools/subdomain_takeover_checker.py`

- [ ] **Step 1: Replace the stub class with the full implementation**

Replace the entire `SubdomainTakeoverChecker` class (from `class SubdomainTakeoverChecker` to end of file) with:

```python
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

            tmp_domains = tmp_subjack = tmp_suspects = tmp_nuclei = None
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
                        "-t", "20", "-ssl", "-a",
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

                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".json", prefix="st_nuclei_", delete=False
                    ) as f:
                        tmp_nuclei = f.name

                    try:
                        await self.run_subprocess([
                            "nuclei", "-l", tmp_suspects,
                            "-t", "/nuclei-templates/custom/",
                            "-t", "/nuclei-templates/community/http/takeovers/",
                            "-json", "-o", tmp_nuclei,
                            "-silent",
                        ])
                    except FileNotFoundError:
                        log.warning(f"{self.name}: nuclei binary not found, skipping Phase 3")
                    except asyncio.TimeoutError:
                        log.warning(f"{self.name}: nuclei timed out, skipping Phase 3")
                    else:
                        if os.path.exists(tmp_nuclei):
                            with open(tmp_nuclei) as f:
                                nuclei_text = f.read()
                            for entry in _parse_nuclei_output(nuclei_text):
                                all_findings.append(_classify_nuclei_result(entry))

            finally:
                for tmp in (tmp_domains, tmp_subjack, tmp_suspects, tmp_nuclei):
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
```

- [ ] **Step 2: Run the full unit test suite — all tests must still pass**

```powershell
pytest tests/unit/config_mgmt/test_subdomain_takeover_checker.py -v
```

Expected: all tests PASS (the pure functions haven't changed).

- [ ] **Step 3: Confirm the import chain is intact**

```powershell
python -c "from workers.config_mgmt.tools.subdomain_takeover_checker import SubdomainTakeoverChecker; print('OK')"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```powershell
git add workers/config_mgmt/tools/subdomain_takeover_checker.py
git commit -m "feat(conf10): implement SubdomainTakeoverChecker.execute() with subjack and nuclei phases"
```

---

## Task 6: Update the Dockerfile

**Files:**
- Modify: `docker/Dockerfile.config_mgmt`

- [ ] **Step 1: Add subjack and nuclei to the Go builder stage**

In `docker/Dockerfile.config_mgmt`, find the Go builder stage. It currently reads:

```dockerfile
RUN go install github.com/ffuf/ffuf/v2@latest
```

Replace that single line with:

```dockerfile
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/haccer/subjack@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

- [ ] **Step 2: Copy binaries and templates in the runtime stage**

In the runtime stage, find the existing binary copy line:

```dockerfile
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/
```

Replace it with:

```dockerfile
COPY --from=go-builder /go/bin/ffuf     /usr/local/bin/
COPY --from=go-builder /go/bin/subjack  /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei   /usr/local/bin/

# Curated takeover templates baked into the image
COPY workers/config_mgmt/nuclei-templates/ /nuclei-templates/custom/

# Community nuclei templates fetched at build time
RUN nuclei -update-templates -ud /nuclei-templates/community || true
```

- [ ] **Step 3: Verify the Dockerfile syntax is valid**

```powershell
docker build --no-cache --target go-builder -f docker/Dockerfile.config_mgmt . 2>&1 | Select-Object -Last 5
```

Expected: ends with `=> exporting to image` or similar success line. (This only builds the Go stage — faster than building the full image.)

- [ ] **Step 4: Commit**

```powershell
git add docker/Dockerfile.config_mgmt
git commit -m "feat(conf10): add subjack and nuclei to config_mgmt Docker image"
```

---

## Task 7: Final verification

- [ ] **Step 1: Run the complete unit test suite**

```powershell
pytest tests/unit/config_mgmt/ -v
```

Expected: all tests in `test_network_config_tester.py`, `test_file_permission_tester.py`, and `test_subdomain_takeover_checker.py` PASS.

- [ ] **Step 2: Confirm the pipeline imports cleanly**

```powershell
python -c "from workers.config_mgmt.pipeline import STAGES; print([s.name for s in STAGES])"
```

Expected output includes `'subdomain_takeover'` at position 12 (index 12):

```
['network_config', 'network_config_cred_test', 'platform_config', 'file_extension_handling', 'backup_files', 'admin_interface_enumeration', 'api_discovery', 'http_methods', 'hsts_testing', 'rpc_testing', 'file_permission', 'file_inclusion', 'subdomain_takeover', 'cloud_storage']
```

- [ ] **Step 3: Confirm concurrency weight is registered**

```powershell
python -c "from workers.config_mgmt.concurrency import get_tool_weight, WeightClass; print(get_tool_weight('subdomain_takeover_checker'))"
```

Expected: `WeightClass.LIGHT`

- [ ] **Step 4: Final commit (if any cleanup needed)**

```powershell
git add -p
git commit -m "chore(conf10): final cleanup and verification"
```
