# WSTG-CONF-07 HSTS Tester Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `HstsTester` from the old subprocess anti-pattern to a pure async `execute()` override that checks HSTS header quality and HTTP→HTTPS redirect behavior across the base target and discovered subdomains.

**Architecture:** Override `execute()` directly (raising `NotImplementedError` from the abstract `build_command`/`parse_output`). Extract all classification logic into module-level pure functions so they can be unit-tested without network or DB. Fan out over discovered hosts via `asyncio.gather` + an inner `asyncio.Semaphore(10)`.

**Tech Stack:** Python 3.12, httpx (async), SQLAlchemy (async), pytest, lib_webbh

---

## File Map

| File | Change |
|---|---|
| `workers/config_mgmt/tools/hsts_tester.py` | Full rewrite |
| `tests/unit/config_mgmt/test_hsts_tester.py` | New — 15 pure-function unit tests |

No changes to `pipeline.py`, `playbooks.py`, `worker-stages.ts`, `concurrency.py`, or `tools/__init__.py`.

---

### Task 1: Write the failing unit tests

**Files:**
- Create: `tests/unit/config_mgmt/test_hsts_tester.py`

- [ ] **Step 1: Create the test file**

```python
"""Unit tests for HstsTester pure helper functions (WSTG-CONF-07)."""
from workers.config_mgmt.tools.hsts_tester import (
    _SECTION_ID,
    _parse_hsts_header,
    _classify_hsts,
    _classify_http_redirect,
    _hsts_on_http,
)


def test_parse_hsts_header_full():
    result = _parse_hsts_header("max-age=31536000; includeSubDomains; preload")
    assert result["max_age"] == 31536000
    assert result["include_subdomains"] is True
    assert result["preload"] is True


def test_parse_hsts_header_max_age_only():
    result = _parse_hsts_header("max-age=3600")
    assert result["max_age"] == 3600
    assert result["include_subdomains"] is False
    assert result["preload"] is False


def test_classify_hsts_missing_header():
    results = _classify_hsts("example.com", "")
    vulns = [r for r in results if "vulnerability" in r]
    assert any(v["vulnerability"]["severity"] == "medium" for v in vulns)


def test_classify_hsts_max_age_too_short():
    results = _classify_hsts("example.com", "max-age=3600; includeSubDomains")
    vulns = [r for r in results if "vulnerability" in r]
    assert any("max-age" in v["vulnerability"]["name"].lower() for v in vulns)
    assert any(v["vulnerability"]["severity"] == "low" for v in vulns)


def test_classify_hsts_missing_include_subdomains():
    results = _classify_hsts("example.com", "max-age=31536000")
    vulns = [r for r in results if "vulnerability" in r]
    assert any("includeSubDomains" in v["vulnerability"]["name"] for v in vulns)
    assert any(v["vulnerability"]["severity"] == "low" for v in vulns)


def test_classify_hsts_no_preload_is_observation_not_vuln():
    results = _classify_hsts("example.com", "max-age=31536000; includeSubDomains")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 0
    obs = [r for r in results if "observation" in r]
    assert any(o["observation"]["value"] == "no_preload" for o in obs)


def test_classify_hsts_compliant():
    results = _classify_hsts("example.com", "max-age=31536000; includeSubDomains; preload")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 0
    obs = [r for r in results if "observation" in r]
    assert any(o["observation"]["value"] == "compliant" for o in obs)


def test_classify_hsts_section_id():
    results = _classify_hsts("example.com", "")
    vulns = [r for r in results if "vulnerability" in r]
    assert all(v["vulnerability"]["section_id"] == "WSTG-CONF-07" for v in vulns)


def test_classify_http_redirect_200_is_high():
    result = _classify_http_redirect("example.com", 200, None)
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"


def test_classify_http_redirect_to_http_is_high():
    result = _classify_http_redirect("example.com", 301, "http://example.com/")
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "high"


def test_classify_http_redirect_to_https_is_observation():
    result = _classify_http_redirect("example.com", 301, "https://example.com/")
    assert "observation" in result
    assert result["observation"]["value"] == "to_https"


def test_classify_http_redirect_section_id():
    result = _classify_http_redirect("example.com", 200, None)
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-07"


def test_hsts_on_http_present_is_low():
    result = _hsts_on_http("example.com", "max-age=31536000")
    assert result is not None
    assert result["vulnerability"]["severity"] == "low"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-07"


def test_hsts_on_http_absent_is_none():
    result = _hsts_on_http("example.com", "")
    assert result is None


def test_section_id_constant():
    assert _SECTION_ID == "WSTG-CONF-07"
```

- [ ] **Step 2: Run tests — confirm they all fail**

```bash
pytest tests/unit/config_mgmt/test_hsts_tester.py -v
```

Expected: 15 ERRORS (ImportError — `_SECTION_ID`, `_parse_hsts_header`, etc. don't exist yet in the new module).

---

### Task 2: Rewrite hsts_tester.py

**Files:**
- Modify: `workers/config_mgmt/tools/hsts_tester.py`

- [ ] **Step 3: Replace the entire file with the rewrite**

```python
"""HSTS configuration tester — WSTG-CONF-07."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf07")

_SECTION_ID = "WSTG-CONF-07"
_MIN_MAX_AGE = 31536000  # 1 year in seconds
_DB_ASSET_TYPES = ["domain", "subdomain"]


# ---------------------------------------------------------------------------
# Pure helper functions — module-level for unit testability
# ---------------------------------------------------------------------------

def _parse_hsts_header(header: str) -> dict:
    """Parse a Strict-Transport-Security header into its directive components."""
    max_age = 0
    m = re.search(r"max-age=(\d+)", header, re.IGNORECASE)
    if m:
        max_age = int(m.group(1))
    return {
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in header.lower(),
        "preload": "preload" in header.lower(),
    }


def _classify_hsts(host: str, header: str) -> list[dict]:
    """Return a list of vuln/observation dicts for the given HSTS header value."""
    if not header:
        return [{"vulnerability": {
            "name": f"Missing HSTS header on {host}",
            "severity": "medium",
            "description": (
                f"The Strict-Transport-Security header is absent on {host}, "
                "leaving users vulnerable to protocol downgrade attacks."
            ),
            "location": f"https://{host}/",
            "section_id": _SECTION_ID,
        }}]

    parsed = _parse_hsts_header(header)
    results: list[dict] = []
    vulns: list[dict] = []

    if parsed["max_age"] < _MIN_MAX_AGE:
        vulns.append({"vulnerability": {
            "name": f"HSTS max-age too short on {host}",
            "severity": "low",
            "description": (
                f"HSTS max-age is {parsed['max_age']}s on {host}. "
                f"Recommended minimum is {_MIN_MAX_AGE} (1 year)."
            ),
            "location": f"https://{host}/",
            "section_id": _SECTION_ID,
        }})

    if not parsed["include_subdomains"]:
        vulns.append({"vulnerability": {
            "name": f"HSTS missing includeSubDomains on {host}",
            "severity": "low",
            "description": (
                f"The HSTS header on {host} lacks the includeSubDomains directive, "
                "leaving subdomains unprotected against downgrade attacks."
            ),
            "location": f"https://{host}/",
            "section_id": _SECTION_ID,
        }})

    results.extend(vulns)

    if not parsed["preload"]:
        results.append({"observation": {
            "type": "hsts_config",
            "value": "no_preload",
            "details": {
                "host": host,
                "header": header,
                "note": "preload directive not set — site cannot be added to HSTS preload list",
            },
        }})

    if not vulns:
        results.append({"observation": {
            "type": "hsts_config",
            "value": "compliant",
            "details": {"host": host, "header": header},
        }})

    return results


def _classify_http_redirect(host: str, status: int, location: str | None) -> dict:
    """Return a vuln or observation dict for an HTTP response's redirect behavior."""
    if status == 200:
        return {"vulnerability": {
            "name": f"HTTP not redirected to HTTPS on {host}",
            "severity": "high",
            "description": (
                f"The HTTP version of {host} returns 200 OK without redirecting "
                "to HTTPS, leaving traffic unencrypted."
            ),
            "location": f"http://{host}/",
            "section_id": _SECTION_ID,
        }}

    if status in (301, 302, 303, 307, 308):
        if location and location.startswith("https://"):
            return {"observation": {
                "type": "http_redirect",
                "value": "to_https",
                "details": {"host": host, "status": status, "location": location},
            }}
        return {"vulnerability": {
            "name": f"HTTP redirects to non-HTTPS URL on {host}",
            "severity": "high",
            "description": (
                f"HTTP request to {host} redirects to {location!r}, which is not HTTPS."
            ),
            "location": f"http://{host}/",
            "section_id": _SECTION_ID,
        }}

    return {"observation": {
        "type": "http_redirect",
        "value": "non_redirect",
        "details": {"host": host, "status": status},
    }}


def _hsts_on_http(host: str, header: str) -> dict | None:
    """Return a low vuln if an HSTS header appears on a plain HTTP response, else None.

    RFC 6797 §8.1: UAs must ignore HSTS headers received over HTTP.
    A server emitting it is misconfigured.
    """
    if not header:
        return None
    return {"vulnerability": {
        "name": f"HSTS header on plain HTTP response on {host}",
        "severity": "low",
        "description": (
            f"RFC 6797 §8.1 requires HSTS headers on HTTP to be ignored. "
            f"Sending HSTS over HTTP is a server misconfiguration on {host}."
        ),
        "location": f"http://{host}/",
        "section_id": _SECTION_ID,
    }}


# ---------------------------------------------------------------------------
# Async probe coroutines — called from execute()
# ---------------------------------------------------------------------------

async def _probe_https(
    client: httpx.AsyncClient,
    host: str,
    sem: asyncio.Semaphore,
) -> list[dict]:
    """GET https://{host}/ and classify the Strict-Transport-Security header."""
    async with sem:
        try:
            resp = await client.get(f"https://{host}/")
            header = resp.headers.get("strict-transport-security", "")
            return _classify_hsts(host, header)
        except httpx.RequestError:
            return []


async def _probe_http(
    client: httpx.AsyncClient,
    host: str,
    sem: asyncio.Semaphore,
) -> list[dict]:
    """GET http://{host}/ and classify redirect behavior + HSTS-on-HTTP."""
    async with sem:
        results: list[dict] = []
        try:
            resp = await client.get(f"http://{host}/")
            location = resp.headers.get("location")
            results.append(_classify_http_redirect(host, resp.status_code, location))
            hsts_finding = _hsts_on_http(
                host, resp.headers.get("strict-transport-security", "")
            )
            if hsts_finding:
                results.append(hsts_finding)
        except httpx.RequestError:
            pass
        return results


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------

class HstsTester(ConfigMgmtTool):
    """Test HTTP Strict Transport Security per WSTG-CONF-07.

    Phases:
    1. HTTPS probe — checks STS header presence, max-age, includeSubDomains, preload
    2. HTTP probe  — checks redirect to HTTPS and absence of STS on plain HTTP
    """

    name = "hsts_tester"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("HstsTester uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("HstsTester uses execute() directly")

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
            base_host = raw.replace("https://", "").replace("http://", "").rstrip("/")

            if not scope_manager.is_in_scope(f"https://{base_host}").in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # Phase 0 — collect hosts from DB (domain + subdomain assets)
            async with get_session() as session:
                stmt = select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(_DB_ASSET_TYPES),
                )
                rows = (await session.execute(stmt)).scalars().all()

            hosts = [
                h for h in rows
                if scope_manager.is_in_scope(f"https://{h}").in_scope
            ]
            if not hosts:
                hosts = [base_host]

            all_results: list[dict] = []

            async with httpx.AsyncClient(
                verify=False, follow_redirects=False, timeout=10,
            ) as client:
                probe_sem = asyncio.Semaphore(10)

                # Phase 1 — HTTPS header quality per host
                p1_tasks = [_probe_https(client, h, probe_sem) for h in hosts]
                for r in await asyncio.gather(*p1_tasks, return_exceptions=True):
                    if isinstance(r, list):
                        all_results.extend(r)

                # Phase 2 — HTTP redirect + HSTS-on-HTTP per host
                p2_tasks = [_probe_http(client, h, probe_sem) for h in hosts]
                for r in await asyncio.gather(*p2_tasks, return_exceptions=True):
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
```

- [ ] **Step 4: Run all 15 unit tests — confirm they all pass**

```bash
pytest tests/unit/config_mgmt/test_hsts_tester.py -v
```

Expected output (all 15 pass):
```
PASSED test_parse_hsts_header_full
PASSED test_parse_hsts_header_max_age_only
PASSED test_classify_hsts_missing_header
PASSED test_classify_hsts_max_age_too_short
PASSED test_classify_hsts_missing_include_subdomains
PASSED test_classify_hsts_no_preload_is_observation_not_vuln
PASSED test_classify_hsts_compliant
PASSED test_classify_hsts_section_id
PASSED test_classify_http_redirect_200_is_high
PASSED test_classify_http_redirect_to_http_is_high
PASSED test_classify_http_redirect_to_https_is_observation
PASSED test_classify_http_redirect_section_id
PASSED test_hsts_on_http_present_is_low
PASSED test_hsts_on_http_absent_is_none
PASSED test_section_id_constant

15 passed
```

- [ ] **Step 5: Run the broader config_mgmt unit suite to confirm no regressions**

```bash
pytest tests/unit/config_mgmt/ -v
```

Expected: all previously-passing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add workers/config_mgmt/tools/hsts_tester.py \
        tests/unit/config_mgmt/test_hsts_tester.py
git commit -m "feat(conf07): rewrite HstsTester — pure async execute, DB-driven hosts, WSTG-CONF-07 section_id"
```
