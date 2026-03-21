# Phase 13 — Reporting & Export Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an on-demand reporting worker that aggregates vulnerability findings from the database and generates professional security reports in Markdown (HackerOne/Bugcrowd) and PDF (executive summary, full technical) formats.

**Architecture:** 4-stage pipeline (data gathering → deduplication/enrichment → rendering → export) triggered via `report_queue` Redis stream. WeasyPrint converts HTML/CSS templates to PDF. Follows existing worker pattern (main.py, pipeline.py, etc.) but uses renderers instead of subprocess tools.

**Tech Stack:** Python 3.10+, SQLAlchemy (async), Jinja2, WeasyPrint, PyYAML, lib_webbh

**Design doc:** `docs/plans/design/2026-03-21-phase13-reporting-worker-design.md`

---

### Task 1: Add cvss_score and remediation columns to Vulnerability model

**Files:**
- Modify: `shared/lib_webbh/database.py:257-275` (Vulnerability class)
- Test: `tests/test_reporting_models.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_models.py`:

```python
# tests/test_reporting_models.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
from lib_webbh.database import Base, Target, Vulnerability, get_engine, get_session


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(company_name="TestCorp", base_domain="testcorp.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.mark.anyio
async def test_vulnerability_has_cvss_score_column(seed_target):
    async with get_session() as session:
        v = Vulnerability(
            target_id=seed_target, severity="high", title="Test XSS",
            cvss_score=7.5,
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        assert v.cvss_score == 7.5


@pytest.mark.anyio
async def test_vulnerability_has_remediation_column(seed_target):
    async with get_session() as session:
        v = Vulnerability(
            target_id=seed_target, severity="medium", title="Test SQLi",
            remediation="Use parameterized queries.",
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        assert v.remediation == "Use parameterized queries."


@pytest.mark.anyio
async def test_vulnerability_new_columns_nullable(seed_target):
    async with get_session() as session:
        v = Vulnerability(
            target_id=seed_target, severity="low", title="Info Disclosure",
        )
        session.add(v)
        await session.commit()
        await session.refresh(v)
        assert v.cvss_score is None
        assert v.remediation is None
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_models.py -v`
Expected: FAIL — `Vulnerability` has no `cvss_score` or `remediation` attributes.

**Step 3: Add the columns to the Vulnerability model**

In `shared/lib_webbh/database.py`, add two new columns to the `Vulnerability` class (after the `source_tool` line, before the relationships):

```python
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_models.py -v`
Expected: 3 passed

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_reporting_models.py
git commit -m "feat(reporting): add cvss_score and remediation columns to Vulnerability model"
```

---

### Task 2: Create reporting worker dataclasses

**Files:**
- Create: `workers/reporting_worker/__init__.py`
- Create: `workers/reporting_worker/models.py`
- Test: `tests/test_reporting_datamodels.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_datamodels.py`:

```python
# tests/test_reporting_datamodels.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from workers.reporting_worker.models import (
    AffectedAsset,
    FindingGroup,
    ReportContext,
    ReportData,
    SummaryStats,
)


def test_summary_stats_total():
    stats = SummaryStats(critical=2, high=3, medium=5, low=1, info=0)
    assert stats.total_findings == 11


def test_finding_group_affected_count():
    group = FindingGroup(
        title="XSS", severity="high", cvss_score=7.5,
        description="Reflected XSS", remediation="Encode output",
        source_tool="nuclei",
        affected_assets=[
            AffectedAsset(asset_value="a.testcorp.com", port=443, protocol="https", service="http", poc="GET /vuln", screenshot_paths=[]),
            AffectedAsset(asset_value="b.testcorp.com", port=80, protocol="http", service="http", poc="GET /vuln2", screenshot_paths=[]),
        ],
    )
    assert len(group.affected_assets) == 2


def test_report_context_defaults():
    ctx = ReportContext(
        target_id=1, company_name="TestCorp", base_domain="testcorp.com",
        target_profile={}, vulnerabilities=[], assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    assert ctx.target_id == 1
    assert ctx.screenshot_map == {}


def test_report_data_construction():
    stats = SummaryStats(critical=1, high=0, medium=0, low=0, info=0)
    data = ReportData(
        company_name="TestCorp", base_domain="testcorp.com",
        finding_groups=[], summary_stats=stats,
        generation_date="2026-03-21", platform="hackerone",
        formats=["hackerone_md"],
        assets=[], cloud_assets=[], api_schemas=[],
    )
    assert data.platform == "hackerone"
    assert data.summary_stats.total_findings == 1
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_datamodels.py -v`
Expected: FAIL — `workers.reporting_worker.models` not found.

**Step 3: Create the models module**

Create `workers/reporting_worker/__init__.py` (empty file).

Create `workers/reporting_worker/models.py`:

```python
"""Dataclasses for the reporting pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AffectedAsset:
    asset_value: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    poc: str | None = None
    screenshot_paths: list[str] = field(default_factory=list)


@dataclass
class FindingGroup:
    title: str
    severity: str
    cvss_score: float
    description: str | None
    remediation: str | None
    source_tool: str | None
    affected_assets: list[AffectedAsset] = field(default_factory=list)


@dataclass
class SummaryStats:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total_findings(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


@dataclass
class ReportContext:
    target_id: int
    company_name: str
    base_domain: str
    target_profile: dict[str, Any]
    vulnerabilities: list[Any]
    assets: list[Any]
    locations: list[Any]
    observations: list[Any]
    cloud_assets: list[Any]
    api_schemas: list[Any]
    screenshot_map: dict[int, list[str]] = field(default_factory=dict)


@dataclass
class ReportData:
    company_name: str
    base_domain: str
    finding_groups: list[FindingGroup]
    summary_stats: SummaryStats
    generation_date: str
    platform: str
    formats: list[str]
    assets: list[Any] = field(default_factory=list)
    cloud_assets: list[Any] = field(default_factory=list)
    api_schemas: list[Any] = field(default_factory=list)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_datamodels.py -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/__init__.py workers/reporting_worker/models.py tests/test_reporting_datamodels.py
git commit -m "feat(reporting): add reporting worker dataclasses"
```

---

### Task 3: Create the remediation map and lookup utility

**Files:**
- Create: `workers/reporting_worker/remediation_map.yaml`
- Create: `workers/reporting_worker/remediation.py`
- Test: `tests/test_reporting_remediation.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_remediation.py`:

```python
# tests/test_reporting_remediation.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from workers.reporting_worker.remediation import lookup_remediation


def test_lookup_xss():
    result = lookup_remediation("Reflected Cross-Site Scripting (XSS)")
    assert result is not None
    assert "sanitiz" in result.lower() or "encod" in result.lower()


def test_lookup_sqli():
    result = lookup_remediation("SQL Injection in login form")
    assert result is not None
    assert "parameterized" in result.lower() or "prepared" in result.lower()


def test_lookup_ssrf():
    result = lookup_remediation("Server-Side Request Forgery")
    assert result is not None


def test_lookup_unknown_returns_generic():
    result = lookup_remediation("Some Unknown Vulnerability Type ZZZZZ")
    assert result is not None
    assert "review" in result.lower() or "assess" in result.lower()


def test_lookup_case_insensitive():
    r1 = lookup_remediation("xss reflected")
    r2 = lookup_remediation("XSS REFLECTED")
    assert r1 == r2
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_remediation.py -v`
Expected: FAIL — module not found.

**Step 3: Create the remediation map and lookup**

Create `workers/reporting_worker/remediation_map.yaml`:

```yaml
xss:
  keywords: ["xss", "cross-site scripting", "cross site scripting"]
  fix: "Sanitize all user input and apply context-aware output encoding. Use Content-Security-Policy headers to restrict inline scripts. Prefer frameworks with auto-escaping (React, Jinja2 with autoescape)."

sqli:
  keywords: ["sql injection", "sqli", "sql inject"]
  fix: "Use parameterized queries or prepared statements for all database interactions. Apply an ORM where possible. Validate and sanitize all user-supplied input before using it in queries."

ssrf:
  keywords: ["ssrf", "server-side request forgery", "server side request forgery"]
  fix: "Validate and whitelist destination URLs. Block requests to internal/private IP ranges (10.x, 127.x, 169.254.x, 172.16-31.x, 192.168.x). Use a dedicated egress proxy for outbound requests."

rce:
  keywords: ["remote code execution", "rce", "command injection", "os command"]
  fix: "Never pass user input directly to shell commands or system calls. Use language-native APIs instead of shell execution. If shell execution is unavoidable, use strict allowlists and parameterized interfaces."

idor:
  keywords: ["idor", "insecure direct object reference", "broken access control", "authorization bypass"]
  fix: "Implement server-side authorization checks on every request. Use indirect object references (UUIDs) instead of sequential IDs. Verify the requesting user owns or has permission to access the resource."

lfi:
  keywords: ["local file inclusion", "lfi", "path traversal", "directory traversal"]
  fix: "Validate file paths against an allowlist of permitted directories. Sanitize path separators and reject inputs containing '..' sequences. Use chroot or containerized environments to limit file access."

open_redirect:
  keywords: ["open redirect", "url redirect", "unvalidated redirect"]
  fix: "Validate redirect URLs against an allowlist of trusted domains. Reject absolute URLs or URLs pointing to external hosts. Use relative paths for internal redirects."

xxe:
  keywords: ["xxe", "xml external entity", "xml injection"]
  fix: "Disable external entity processing in XML parsers. Use JSON instead of XML where possible. Configure parsers to disallow DTDs and external entity resolution."

csrf:
  keywords: ["csrf", "cross-site request forgery", "cross site request forgery"]
  fix: "Implement anti-CSRF tokens (synchronizer pattern) on all state-changing forms. Use SameSite cookie attribute. Verify Origin/Referer headers on incoming requests."

cors:
  keywords: ["cors", "cross-origin", "access-control-allow-origin"]
  fix: "Configure Access-Control-Allow-Origin to specific trusted domains, never use wildcard (*) with credentials. Validate the Origin header server-side. Remove Access-Control-Allow-Credentials unless required."

missing_headers:
  keywords: ["missing header", "security header", "x-frame-options", "x-content-type", "strict-transport", "hsts", "content-security-policy"]
  fix: "Add security headers: X-Frame-Options (DENY or SAMEORIGIN), X-Content-Type-Options (nosniff), Strict-Transport-Security (max-age=31536000; includeSubDomains), Content-Security-Policy, and Referrer-Policy."

ssl_tls:
  keywords: ["ssl", "tls", "certificate", "weak cipher", "expired cert"]
  fix: "Use TLS 1.2+ only. Disable SSLv3, TLS 1.0, and TLS 1.1. Use strong cipher suites (AES-GCM, ChaCha20). Ensure certificates are valid and not expired."

information_disclosure:
  keywords: ["information disclosure", "info disclosure", "sensitive data", "data exposure", "verbose error"]
  fix: "Remove verbose error messages in production. Disable server version headers. Review responses for leaked internal paths, stack traces, or credentials."

subdomain_takeover:
  keywords: ["subdomain takeover", "dangling cname", "unclaimed subdomain"]
  fix: "Remove DNS records pointing to decommissioned services. Regularly audit CNAME records for dangling references. Claim or reserve service endpoints before configuring DNS."
```

Create `workers/reporting_worker/remediation.py`:

```python
"""Remediation advice lookup from static map."""
from __future__ import annotations

from pathlib import Path

import yaml

_MAP_PATH = Path(__file__).parent / "remediation_map.yaml"
_GENERIC = "Review the vulnerability details and assess the affected component. Apply the principle of least privilege and follow OWASP remediation guidelines for this class of issue."

_cache: list[tuple[list[str], str]] | None = None


def _load_map() -> list[tuple[list[str], str]]:
    global _cache
    if _cache is not None:
        return _cache
    data = yaml.safe_load(_MAP_PATH.read_text())
    _cache = [(entry["keywords"], entry["fix"]) for entry in data.values()]
    return _cache


def lookup_remediation(title: str) -> str:
    title_lower = title.lower()
    for keywords, fix in _load_map():
        if any(kw in title_lower for kw in keywords):
            return fix
    return _GENERIC
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_remediation.py -v`
Expected: 5 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/remediation_map.yaml workers/reporting_worker/remediation.py tests/test_reporting_remediation.py
git commit -m "feat(reporting): add remediation lookup with static YAML map"
```

---

### Task 4: Create the data gatherer (Stage 1)

**Files:**
- Create: `workers/reporting_worker/data_gatherer.py`
- Test: `tests/test_reporting_data_gatherer.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_data_gatherer.py`:

```python
# tests/test_reporting_data_gatherer.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
from lib_webbh.database import (
    Asset, Base, CloudAsset, Location, Observation, Target, Vulnerability,
    get_engine, get_session,
)
from workers.reporting_worker.data_gatherer import gather_report_data


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_data(db):
    async with get_session() as session:
        t = Target(company_name="AcmeCorp", base_domain="acme.com", target_profile={"in_scope_domains": ["*.acme.com"]})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.acme.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        loc = Location(asset_id=a.id, port=443, protocol="https", service="http", state="open")
        session.add(loc)

        obs = Observation(asset_id=a.id, tech_stack={"framework": "React"}, status_code=200)
        session.add(obs)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="Reflected XSS", description="XSS in search param",
            poc="GET /search?q=<script>alert(1)</script>", source_tool="nuclei",
        )
        session.add(v)

        ca = CloudAsset(target_id=t.id, provider="aws", asset_type="s3", url="https://acme-backup.s3.amazonaws.com", is_public=True)
        session.add(ca)

        await session.commit()
        return t.id


@pytest.mark.anyio
async def test_gather_returns_report_context(seed_data):
    ctx = await gather_report_data(seed_data, screenshot_base="/nonexistent")
    assert ctx.target_id == seed_data
    assert ctx.company_name == "AcmeCorp"
    assert ctx.base_domain == "acme.com"
    assert len(ctx.vulnerabilities) == 1
    assert len(ctx.assets) == 1
    assert len(ctx.cloud_assets) == 1


@pytest.mark.anyio
async def test_gather_empty_target(db):
    async with get_session() as session:
        t = Target(company_name="EmptyCorp", base_domain="empty.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        tid = t.id
    ctx = await gather_report_data(tid, screenshot_base="/nonexistent")
    assert ctx.vulnerabilities == []
    assert ctx.assets == []
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_data_gatherer.py -v`
Expected: FAIL — module not found.

**Step 3: Implement data_gatherer.py**

Create `workers/reporting_worker/data_gatherer.py`:

```python
"""Stage 1: Gather all report data from the database."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from lib_webbh.database import (
    ApiSchema, Asset, CloudAsset, Location, Observation, Target, Vulnerability,
    get_session,
)
from workers.reporting_worker.models import ReportContext


async def gather_report_data(target_id: int, screenshot_base: str = "/app/shared/raw") -> ReportContext:
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one()

        vulns = (await session.execute(
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset).selectinload(Asset.locations))
        )).scalars().all()

        assets = (await session.execute(
            select(Asset)
            .where(Asset.target_id == target_id)
            .options(selectinload(Asset.locations))
        )).scalars().all()

        locations = (await session.execute(
            select(Location).join(Asset).where(Asset.target_id == target_id)
        )).scalars().all()

        observations = (await session.execute(
            select(Observation).join(Asset).where(Asset.target_id == target_id)
        )).scalars().all()

        cloud_assets = (await session.execute(
            select(CloudAsset).where(CloudAsset.target_id == target_id)
        )).scalars().all()

        api_schemas = (await session.execute(
            select(ApiSchema).where(ApiSchema.target_id == target_id)
        )).scalars().all()

    screenshot_map = _scan_screenshots(target_id, screenshot_base)

    return ReportContext(
        target_id=target_id,
        company_name=target.company_name,
        base_domain=target.base_domain,
        target_profile=target.target_profile or {},
        vulnerabilities=list(vulns),
        assets=list(assets),
        locations=list(locations),
        observations=list(observations),
        cloud_assets=list(cloud_assets),
        api_schemas=list(api_schemas),
        screenshot_map=screenshot_map,
    )


def _scan_screenshots(target_id: int, base: str) -> dict[int, list[str]]:
    """Scan the shared raw directory for screenshots, keyed by asset_id."""
    target_dir = Path(base) / str(target_id)
    result: dict[int, list[str]] = {}
    if not target_dir.is_dir():
        return result
    for img in target_dir.glob("**/*.png"):
        # Convention: screenshots named {asset_id}_*.png
        try:
            asset_id = int(img.stem.split("_")[0])
            result.setdefault(asset_id, []).append(str(img))
        except (ValueError, IndexError):
            continue
    return result
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_data_gatherer.py -v`
Expected: 2 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/data_gatherer.py tests/test_reporting_data_gatherer.py
git commit -m "feat(reporting): add data gatherer (pipeline stage 1)"
```

---

### Task 5: Create the deduplicator and enrichment module (Stage 2)

**Files:**
- Create: `workers/reporting_worker/deduplicator.py`
- Test: `tests/test_reporting_deduplicator.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_deduplicator.py`:

```python
# tests/test_reporting_deduplicator.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from unittest.mock import MagicMock
from workers.reporting_worker.deduplicator import deduplicate_and_enrich
from workers.reporting_worker.models import ReportContext


def _make_vuln(title, severity, source_tool, asset_value=None, poc=None, asset_id=None, cvss_score=None, remediation=None):
    v = MagicMock()
    v.title = title
    v.severity = severity
    v.source_tool = source_tool
    v.poc = poc
    v.cvss_score = cvss_score
    v.remediation = remediation
    v.description = f"Description of {title}"
    v.asset_id = asset_id
    if asset_value:
        v.asset = MagicMock()
        v.asset.asset_value = asset_value
        v.asset.locations = [MagicMock(port=443, protocol="https", service="http")]
    else:
        v.asset = None
    return v


def test_groups_by_source_title_severity():
    vulns = [
        _make_vuln("XSS", "high", "nuclei", "a.com", asset_id=1),
        _make_vuln("XSS", "high", "nuclei", "b.com", asset_id=2),
        _make_vuln("XSS", "medium", "nuclei", "c.com", asset_id=3),
    ]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    # "XSS/high/nuclei" and "XSS/medium/nuclei" = 2 groups
    assert len(data.finding_groups) == 2


def test_cvss_fallback_when_null():
    vulns = [_make_vuln("SQLi", "critical", "sqlmap", "d.com", asset_id=1)]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert data.finding_groups[0].cvss_score == 9.5  # critical midpoint


def test_cvss_uses_column_when_present():
    vulns = [_make_vuln("SQLi", "critical", "sqlmap", "d.com", asset_id=1, cvss_score=9.8)]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert data.finding_groups[0].cvss_score == 9.8


def test_sorted_by_cvss_descending():
    vulns = [
        _make_vuln("Info Leak", "low", "nuclei", "a.com", asset_id=1),
        _make_vuln("RCE", "critical", "nuclei", "b.com", asset_id=2),
        _make_vuln("XSS", "high", "nuclei", "c.com", asset_id=3),
    ]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    scores = [g.cvss_score for g in data.finding_groups]
    assert scores == sorted(scores, reverse=True)


def test_summary_stats_counts():
    vulns = [
        _make_vuln("A", "critical", "t", "a.com", asset_id=1),
        _make_vuln("B", "high", "t", "b.com", asset_id=2),
        _make_vuln("C", "high", "t", "c.com", asset_id=3),
        _make_vuln("D", "medium", "t", "d.com", asset_id=4),
    ]
    ctx = ReportContext(
        target_id=1, company_name="T", base_domain="t.com",
        target_profile={}, vulnerabilities=vulns, assets=[], locations=[],
        observations=[], cloud_assets=[], api_schemas=[], screenshot_map={},
    )
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])
    assert data.summary_stats.critical == 1
    assert data.summary_stats.high == 2
    assert data.summary_stats.medium == 1
    assert data.summary_stats.total_findings == 4
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_deduplicator.py -v`
Expected: FAIL — module not found.

**Step 3: Implement deduplicator.py**

Create `workers/reporting_worker/deduplicator.py`:

```python
"""Stage 2: Deduplicate findings and enrich with CVSS/remediation."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from workers.reporting_worker.models import (
    AffectedAsset,
    FindingGroup,
    ReportData,
    ReportContext,
    SummaryStats,
)
from workers.reporting_worker.remediation import lookup_remediation

SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
    "informational": 0.0,
}


def deduplicate_and_enrich(ctx: ReportContext, platform: str, formats: list[str]) -> ReportData:
    groups_map: dict[tuple[str | None, str, str], list[Any]] = defaultdict(list)

    for v in ctx.vulnerabilities:
        key = (v.source_tool, v.title, v.severity)
        groups_map[key].append(v)

    finding_groups: list[FindingGroup] = []
    severity_counts: dict[str, int] = defaultdict(int)

    for (source_tool, title, severity), vulns in groups_map.items():
        first = vulns[0]
        cvss = first.cvss_score if first.cvss_score is not None else SEVERITY_CVSS.get(severity.lower(), 0.0)
        remediation = first.remediation if first.remediation else lookup_remediation(title)

        affected: list[AffectedAsset] = []
        for v in vulns:
            if v.asset:
                loc = v.asset.locations[0] if v.asset.locations else None
                affected.append(AffectedAsset(
                    asset_value=v.asset.asset_value,
                    port=loc.port if loc else None,
                    protocol=loc.protocol if loc else None,
                    service=loc.service if loc else None,
                    poc=v.poc,
                    screenshot_paths=ctx.screenshot_map.get(v.asset_id, []),
                ))
            else:
                affected.append(AffectedAsset(
                    asset_value="(target-wide)",
                    poc=v.poc,
                ))

        finding_groups.append(FindingGroup(
            title=title,
            severity=severity,
            cvss_score=cvss,
            description=first.description,
            remediation=remediation,
            source_tool=source_tool,
            affected_assets=affected,
        ))
        severity_counts[severity.lower()] += 1

    finding_groups.sort(key=lambda g: g.cvss_score, reverse=True)

    stats = SummaryStats(
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0) + severity_counts.get("informational", 0),
    )

    return ReportData(
        company_name=ctx.company_name,
        base_domain=ctx.base_domain,
        finding_groups=finding_groups,
        summary_stats=stats,
        generation_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        platform=platform,
        formats=formats,
        assets=ctx.assets,
        cloud_assets=ctx.cloud_assets,
        api_schemas=ctx.api_schemas,
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_deduplicator.py -v`
Expected: 5 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/deduplicator.py tests/test_reporting_deduplicator.py
git commit -m "feat(reporting): add deduplicator and enrichment (pipeline stage 2)"
```

---

### Task 6: Create the base renderer and markdown renderer

**Files:**
- Create: `workers/reporting_worker/base_renderer.py`
- Create: `workers/reporting_worker/renderers/__init__.py`
- Create: `workers/reporting_worker/renderers/markdown_renderer.py`
- Create: `workers/reporting_worker/templates/hackerone.md.j2`
- Create: `workers/reporting_worker/templates/bugcrowd.md.j2`
- Test: `tests/test_reporting_markdown_renderer.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_markdown_renderer.py`:

```python
# tests/test_reporting_markdown_renderer.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
from workers.reporting_worker.models import (
    AffectedAsset, FindingGroup, ReportData, SummaryStats,
)
from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer


@pytest.fixture
def sample_report_data():
    return ReportData(
        company_name="AcmeCorp", base_domain="acme.com",
        finding_groups=[
            FindingGroup(
                title="Reflected XSS", severity="high", cvss_score=7.5,
                description="XSS in search parameter",
                remediation="Encode all output.",
                source_tool="nuclei",
                affected_assets=[
                    AffectedAsset(
                        asset_value="app.acme.com", port=443, protocol="https",
                        service="http",
                        poc="GET /search?q=<script>alert(1)</script>\nHTTP/1.1 200 OK\n...",
                        screenshot_paths=[],
                    ),
                ],
            ),
        ],
        summary_stats=SummaryStats(critical=0, high=1, medium=0, low=0, info=0),
        generation_date="2026-03-21", platform="hackerone",
        formats=["hackerone_md"], assets=[], cloud_assets=[], api_schemas=[],
    )


def test_markdown_renderer_produces_files(sample_report_data):
    renderer = MarkdownRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = renderer.render(sample_report_data, output_dir=tmpdir)
        assert len(paths) >= 1
        for p in paths:
            assert os.path.exists(p)
            assert p.endswith(".md")


def test_hackerone_template_has_required_sections(sample_report_data):
    renderer = MarkdownRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = renderer.render(sample_report_data, output_dir=tmpdir)
        # Read the index/first file
        content = open(paths[0]).read()
        assert "Reflected XSS" in content
        assert "high" in content.lower() or "7.5" in content


def test_bugcrowd_template(sample_report_data):
    sample_report_data.platform = "bugcrowd"
    renderer = MarkdownRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = renderer.render(sample_report_data, output_dir=tmpdir)
        assert len(paths) >= 1
        content = open(paths[0]).read()
        assert "Reflected XSS" in content
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_markdown_renderer.py -v`
Expected: FAIL — module not found.

**Step 3: Implement the base renderer, markdown renderer, and templates**

Create `workers/reporting_worker/base_renderer.py`:

```python
"""Base class for report renderers."""
from __future__ import annotations

from abc import ABC, abstractmethod

from workers.reporting_worker.models import ReportData


class BaseRenderer(ABC):
    @abstractmethod
    def render(self, data: ReportData, output_dir: str) -> list[str]:
        """Render the report and return list of output file paths."""
```

Create `workers/reporting_worker/renderers/__init__.py`:

```python
from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer

__all__ = ["MarkdownRenderer"]
```

Create `workers/reporting_worker/templates/hackerone.md.j2`:

```
# Security Assessment Report — {{ company_name }} ({{ base_domain }})

**Date:** {{ generation_date }}
**Total Findings:** {{ summary_stats.total_findings }}
**Severity Breakdown:** Critical: {{ summary_stats.critical }} | High: {{ summary_stats.high }} | Medium: {{ summary_stats.medium }} | Low: {{ summary_stats.low }} | Info: {{ summary_stats.info }}

---
{% for group in finding_groups %}

## {{ group.title }}

**Severity:** {{ group.severity | upper }}
**CVSS Score:** {{ group.cvss_score }}
**Source Tool:** {{ group.source_tool or "Manual" }}

### Summary

{{ group.description or "No description available." }}

### Steps To Reproduce
{% for asset in group.affected_assets %}

**Asset:** {{ asset.asset_value }}{% if asset.port %} ({{ asset.protocol }}://{{ asset.asset_value }}:{{ asset.port }}){% endif %}

```
{{ asset.poc or "No PoC available." }}
```
{% endfor %}

### Impact

This vulnerability is rated **{{ group.severity | upper }}** (CVSS {{ group.cvss_score }}). {% if group.severity.lower() == "critical" %}Immediate remediation is strongly recommended.{% elif group.severity.lower() == "high" %}Remediation should be prioritized.{% else %}Review and remediate as part of regular security maintenance.{% endif %}

### Recommended Fix

{{ group.remediation or "No specific remediation advice available." }}

---
{% endfor %}
```

Create `workers/reporting_worker/templates/bugcrowd.md.j2`:

```
# Vulnerability Report — {{ company_name }} ({{ base_domain }})

**Report Date:** {{ generation_date }}
**Findings:** {{ summary_stats.total_findings }} total (Critical: {{ summary_stats.critical }}, High: {{ summary_stats.high }}, Medium: {{ summary_stats.medium }}, Low: {{ summary_stats.low }}, Info: {{ summary_stats.info }})

---
{% for group in finding_groups %}

## [{{ group.severity | upper }}] {{ group.title }}

**CVSS:** {{ group.cvss_score }} | **Tool:** {{ group.source_tool or "Manual" }}

### Description

{{ group.description or "No description available." }}

### Proof of Concept
{% for asset in group.affected_assets %}

**Target:** {{ asset.asset_value }}{% if asset.port %} (port {{ asset.port }}){% endif %}

```
{{ asset.poc or "No PoC available." }}
```
{% endfor %}

### Affected Assets
{% for asset in group.affected_assets %}
- {{ asset.asset_value }}{% if asset.port %} ({{ asset.protocol }}:{{ asset.port }}){% endif %}
{% endfor %}

### Remediation

{{ group.remediation or "No specific remediation advice available." }}

---
{% endfor %}
```

Create `workers/reporting_worker/renderers/markdown_renderer.py`:

```python
"""Markdown report renderer for HackerOne/Bugcrowd formats."""
from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from workers.reporting_worker.base_renderer import BaseRenderer
from workers.reporting_worker.models import ReportData

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

PLATFORM_TEMPLATES = {
    "hackerone": "hackerone.md.j2",
    "bugcrowd": "bugcrowd.md.j2",
}


class MarkdownRenderer(BaseRenderer):
    def render(self, data: ReportData, output_dir: str) -> list[str]:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=False)
        template_name = PLATFORM_TEMPLATES.get(data.platform, "hackerone.md.j2")
        template = env.get_template(template_name)

        rendered = template.render(
            company_name=data.company_name,
            base_domain=data.base_domain,
            generation_date=data.generation_date,
            summary_stats=data.summary_stats,
            finding_groups=data.finding_groups,
        )

        os.makedirs(output_dir, exist_ok=True)
        filename = f"{data.company_name}_{data.generation_date}_{data.platform}.md"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w") as f:
            f.write(rendered)

        return [filepath]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_markdown_renderer.py -v`
Expected: 3 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/base_renderer.py \
       workers/reporting_worker/renderers/__init__.py \
       workers/reporting_worker/renderers/markdown_renderer.py \
       workers/reporting_worker/templates/hackerone.md.j2 \
       workers/reporting_worker/templates/bugcrowd.md.j2 \
       tests/test_reporting_markdown_renderer.py
git commit -m "feat(reporting): add markdown renderer with HackerOne/Bugcrowd templates"
```

---

### Task 7: Create the PDF renderers (executive + technical)

**Files:**
- Create: `workers/reporting_worker/renderers/executive_renderer.py`
- Create: `workers/reporting_worker/renderers/technical_renderer.py`
- Create: `workers/reporting_worker/templates/executive.html.j2`
- Create: `workers/reporting_worker/templates/executive.css`
- Create: `workers/reporting_worker/templates/technical.html.j2`
- Create: `workers/reporting_worker/templates/technical.css`
- Create: `workers/reporting_worker/templates/_partials/_header.html.j2`
- Create: `workers/reporting_worker/templates/_partials/_stats.html.j2`
- Create: `workers/reporting_worker/templates/_partials/_finding.html.j2`
- Modify: `workers/reporting_worker/renderers/__init__.py`
- Test: `tests/test_reporting_pdf_renderers.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_pdf_renderers.py`:

```python
# tests/test_reporting_pdf_renderers.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
from workers.reporting_worker.models import (
    AffectedAsset, FindingGroup, ReportData, SummaryStats,
)
from workers.reporting_worker.renderers.executive_renderer import ExecutiveRenderer
from workers.reporting_worker.renderers.technical_renderer import TechnicalRenderer


@pytest.fixture
def sample_report_data():
    return ReportData(
        company_name="AcmeCorp", base_domain="acme.com",
        finding_groups=[
            FindingGroup(
                title="SQL Injection", severity="critical", cvss_score=9.8,
                description="SQLi in login endpoint",
                remediation="Use parameterized queries.",
                source_tool="sqlmap",
                affected_assets=[
                    AffectedAsset(
                        asset_value="api.acme.com", port=443, protocol="https",
                        service="http",
                        poc="POST /login\nusername=admin'--\n\nHTTP/1.1 500",
                        screenshot_paths=[],
                    ),
                ],
            ),
            FindingGroup(
                title="Missing HSTS", severity="low", cvss_score=2.0,
                description="HSTS header not set",
                remediation="Add Strict-Transport-Security header.",
                source_tool="nuclei",
                affected_assets=[
                    AffectedAsset(asset_value="www.acme.com", port=443, protocol="https", service="http", poc=None, screenshot_paths=[]),
                ],
            ),
        ],
        summary_stats=SummaryStats(critical=1, high=0, medium=0, low=1, info=0),
        generation_date="2026-03-21", platform="hackerone",
        formats=["executive_pdf", "technical_pdf"],
        assets=[], cloud_assets=[], api_schemas=[],
    )


def test_executive_renders_html(sample_report_data):
    """Test that executive renderer produces valid HTML (before WeasyPrint)."""
    renderer = ExecutiveRenderer()
    html = renderer.render_html(sample_report_data)
    assert "<html" in html
    assert "AcmeCorp" in html
    assert "SQL Injection" in html


def test_technical_renders_html(sample_report_data):
    """Test that technical renderer produces valid HTML with PoC blocks."""
    renderer = TechnicalRenderer()
    html = renderer.render_html(sample_report_data)
    assert "<html" in html
    assert "SQL Injection" in html
    assert "POST /login" in html  # PoC content
    assert "parameterized" in html  # remediation


def test_executive_render_to_file(sample_report_data):
    """Test full PDF render if WeasyPrint is available, otherwise test HTML fallback."""
    renderer = ExecutiveRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            paths = renderer.render(sample_report_data, output_dir=tmpdir)
            assert len(paths) == 1
            assert paths[0].endswith(".pdf")
            assert os.path.getsize(paths[0]) > 0
        except ImportError:
            pytest.skip("WeasyPrint not installed")


def test_technical_render_to_file(sample_report_data):
    """Test full PDF render if WeasyPrint is available, otherwise test HTML fallback."""
    renderer = TechnicalRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            paths = renderer.render(sample_report_data, output_dir=tmpdir)
            assert len(paths) == 1
            assert paths[0].endswith(".pdf")
            assert os.path.getsize(paths[0]) > 0
        except ImportError:
            pytest.skip("WeasyPrint not installed")
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_pdf_renderers.py -v`
Expected: FAIL — modules not found.

**Step 3: Create template partials, HTML templates, CSS, and renderers**

Create `workers/reporting_worker/templates/_partials/_header.html.j2`:

```html
<header class="report-header">
    <h1>{{ title }}</h1>
    <div class="meta">
        <p><strong>Target:</strong> {{ company_name }} ({{ base_domain }})</p>
        <p><strong>Date:</strong> {{ generation_date }}</p>
    </div>
</header>
```

Create `workers/reporting_worker/templates/_partials/_stats.html.j2`:

```html
<section class="severity-summary">
    <h2>Severity Distribution</h2>
    <div class="stats-bar">
        {% if summary_stats.critical > 0 %}
        <div class="bar-segment critical" style="flex: {{ summary_stats.critical }};">{{ summary_stats.critical }} Critical</div>
        {% endif %}
        {% if summary_stats.high > 0 %}
        <div class="bar-segment high" style="flex: {{ summary_stats.high }};">{{ summary_stats.high }} High</div>
        {% endif %}
        {% if summary_stats.medium > 0 %}
        <div class="bar-segment medium" style="flex: {{ summary_stats.medium }};">{{ summary_stats.medium }} Medium</div>
        {% endif %}
        {% if summary_stats.low > 0 %}
        <div class="bar-segment low" style="flex: {{ summary_stats.low }};">{{ summary_stats.low }} Low</div>
        {% endif %}
        {% if summary_stats.info > 0 %}
        <div class="bar-segment info" style="flex: {{ summary_stats.info }};">{{ summary_stats.info }} Info</div>
        {% endif %}
    </div>
    <p class="total">Total Findings: {{ summary_stats.total_findings }}</p>
</section>
```

Create `workers/reporting_worker/templates/_partials/_finding.html.j2`:

```html
<section class="finding severity-{{ group.severity | lower }}">
    <h3>{{ group.title }}</h3>
    <table class="finding-meta">
        <tr><td><strong>Severity</strong></td><td class="sev-{{ group.severity | lower }}">{{ group.severity | upper }}</td></tr>
        <tr><td><strong>CVSS Score</strong></td><td>{{ group.cvss_score }}</td></tr>
        <tr><td><strong>Source Tool</strong></td><td>{{ group.source_tool or "Manual" }}</td></tr>
        <tr><td><strong>Affected Assets</strong></td><td>{{ group.affected_assets | length }}</td></tr>
    </table>

    <h4>Description</h4>
    <p>{{ group.description or "No description available." }}</p>

    {% if show_poc %}
    <h4>Proof of Concept</h4>
    {% for asset in group.affected_assets %}
    <div class="poc-block">
        <p class="asset-label"><strong>{{ asset.asset_value }}</strong>{% if asset.port %} ({{ asset.protocol }}://{{ asset.asset_value }}:{{ asset.port }}){% endif %}</p>
        {% if asset.poc %}
        <pre class="poc">{{ asset.poc | e }}</pre>
        {% endif %}
        {% for img_path in asset.screenshot_paths %}
        <img src="{{ img_path }}" alt="Screenshot for {{ asset.asset_value }}" class="screenshot" />
        {% endfor %}
    </div>
    {% endfor %}
    {% endif %}

    <h4>Remediation</h4>
    <p>{{ group.remediation or "No specific remediation advice available." }}</p>
</section>
```

Create `workers/reporting_worker/templates/executive.html.j2`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="executive.css">
    <title>Executive Summary — {{ company_name }}</title>
</head>
<body>
    <div class="cover">
        <h1>Security Assessment</h1>
        <h2>Executive Summary</h2>
        <p class="target">{{ company_name }} — {{ base_domain }}</p>
        <p class="date">{{ generation_date }}</p>
    </div>

    <div class="page-break"></div>

    {% include '_partials/_stats.html.j2' %}

    <section class="findings-table">
        <h2>Findings Overview</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Affected Assets</th>
                </tr>
            </thead>
            <tbody>
                {% for group in finding_groups %}
                <tr class="sev-row-{{ group.severity | lower }}">
                    <td>{{ loop.index }}</td>
                    <td>{{ group.title }}</td>
                    <td class="sev-{{ group.severity | lower }}">{{ group.severity | upper }}</td>
                    <td>{{ group.cvss_score }}</td>
                    <td>{{ group.affected_assets | length }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </section>
</body>
</html>
```

Create `workers/reporting_worker/templates/executive.css`:

```css
@page { size: A4; margin: 2cm; }
body { font-family: "Helvetica Neue", Arial, sans-serif; color: #333; line-height: 1.5; }
.cover { text-align: center; padding-top: 30%; }
.cover h1 { font-size: 32pt; color: #1a1a2e; margin-bottom: 10px; }
.cover h2 { font-size: 20pt; color: #555; margin-bottom: 40px; }
.cover .target { font-size: 14pt; }
.cover .date { font-size: 12pt; color: #888; }
.page-break { page-break-after: always; }
h2 { color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 5px; }
.stats-bar { display: flex; height: 40px; border-radius: 4px; overflow: hidden; margin: 15px 0; }
.bar-segment { color: white; display: flex; align-items: center; justify-content: center; font-size: 10pt; font-weight: bold; }
.bar-segment.critical { background: #dc3545; }
.bar-segment.high { background: #fd7e14; }
.bar-segment.medium { background: #ffc107; color: #333; }
.bar-segment.low { background: #28a745; }
.bar-segment.info { background: #6c757d; }
.total { font-size: 14pt; font-weight: bold; }
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th { background: #1a1a2e; color: white; padding: 8px 12px; text-align: left; }
td { padding: 8px 12px; border-bottom: 1px solid #ddd; }
.sev-critical { color: #dc3545; font-weight: bold; }
.sev-high { color: #fd7e14; font-weight: bold; }
.sev-medium { color: #d4a017; font-weight: bold; }
.sev-low { color: #28a745; }
.sev-info { color: #6c757d; }
.sev-row-critical { border-left: 4px solid #dc3545; }
.sev-row-high { border-left: 4px solid #fd7e14; }
.sev-row-medium { border-left: 4px solid #ffc107; }
.sev-row-low { border-left: 4px solid #28a745; }
```

Create `workers/reporting_worker/templates/technical.html.j2`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="technical.css">
    <title>Technical Security Report — {{ company_name }}</title>
</head>
<body>
    <div class="cover">
        <h1>Security Assessment</h1>
        <h2>Full Technical Report</h2>
        <p class="target">{{ company_name }} — {{ base_domain }}</p>
        <p class="date">{{ generation_date }}</p>
    </div>

    <div class="page-break"></div>

    <h2>Table of Contents</h2>
    <ol class="toc">
        <li><a href="#summary">Executive Summary</a></li>
        <li><a href="#findings">Detailed Findings</a></li>
        {% for group in finding_groups %}
        <li class="toc-finding"><a href="#finding-{{ loop.index }}">{{ group.title }} [{{ group.severity | upper }}]</a></li>
        {% endfor %}
        <li><a href="#appendix">Appendices</a></li>
    </ol>

    <div class="page-break"></div>

    <section id="summary">
        <h2>Executive Summary</h2>
        {% include '_partials/_stats.html.j2' %}
    </section>

    <div class="page-break"></div>

    <section id="findings">
        <h2>Detailed Findings</h2>
        {% for group in finding_groups %}
        <div id="finding-{{ loop.index }}">
            {% with show_poc=true %}
            {% include '_partials/_finding.html.j2' %}
            {% endwith %}
        </div>
        {% if not loop.last %}<div class="page-break"></div>{% endif %}
        {% endfor %}
    </section>

    <div class="page-break"></div>

    <section id="appendix">
        <h2>Appendices</h2>

        <h3>A. Asset Inventory</h3>
        {% if assets %}
        <table>
            <thead><tr><th>Asset</th><th>Type</th><th>Source</th></tr></thead>
            <tbody>
                {% for a in assets %}
                <tr><td>{{ a.asset_value }}</td><td>{{ a.asset_type }}</td><td>{{ a.source_tool or "-" }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No assets recorded.</p>
        {% endif %}

        <h3>B. Cloud Assets</h3>
        {% if cloud_assets %}
        <table>
            <thead><tr><th>Provider</th><th>Type</th><th>URL</th><th>Public</th></tr></thead>
            <tbody>
                {% for ca in cloud_assets %}
                <tr><td>{{ ca.provider }}</td><td>{{ ca.asset_type }}</td><td>{{ ca.url or "-" }}</td><td>{{ "Yes" if ca.is_public else "No" }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No cloud assets recorded.</p>
        {% endif %}

        <h3>C. API Schemas</h3>
        {% if api_schemas %}
        <table>
            <thead><tr><th>Method</th><th>Path</th><th>Auth Required</th></tr></thead>
            <tbody>
                {% for s in api_schemas %}
                <tr><td>{{ s.method }}</td><td>{{ s.path }}</td><td>{{ "Yes" if s.auth_required else "No" }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No API schemas recorded.</p>
        {% endif %}
    </section>
</body>
</html>
```

Create `workers/reporting_worker/templates/technical.css`:

```css
@page { size: A4; margin: 2cm; @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 9pt; color: #888; } }
body { font-family: "Helvetica Neue", Arial, sans-serif; color: #333; line-height: 1.5; }
.cover { text-align: center; padding-top: 30%; }
.cover h1 { font-size: 32pt; color: #1a1a2e; margin-bottom: 10px; }
.cover h2 { font-size: 20pt; color: #555; margin-bottom: 40px; }
.cover .target { font-size: 14pt; }
.cover .date { font-size: 12pt; color: #888; }
.page-break { page-break-after: always; }
h2 { color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 5px; margin-top: 20px; }
h3 { color: #333; margin-top: 15px; }
h4 { color: #555; margin-top: 10px; }
.toc { font-size: 12pt; }
.toc li { margin: 4px 0; }
.toc-finding { margin-left: 20px; }
.stats-bar { display: flex; height: 40px; border-radius: 4px; overflow: hidden; margin: 15px 0; }
.bar-segment { color: white; display: flex; align-items: center; justify-content: center; font-size: 10pt; font-weight: bold; }
.bar-segment.critical { background: #dc3545; }
.bar-segment.high { background: #fd7e14; }
.bar-segment.medium { background: #ffc107; color: #333; }
.bar-segment.low { background: #28a745; }
.bar-segment.info { background: #6c757d; }
.total { font-size: 14pt; font-weight: bold; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th { background: #1a1a2e; color: white; padding: 6px 10px; text-align: left; font-size: 10pt; }
td { padding: 6px 10px; border-bottom: 1px solid #ddd; font-size: 10pt; }
.finding { margin-bottom: 20px; padding: 15px; border-radius: 4px; border-left: 4px solid #ccc; }
.finding.severity-critical { border-left-color: #dc3545; background: #fff5f5; }
.finding.severity-high { border-left-color: #fd7e14; background: #fff8f0; }
.finding.severity-medium { border-left-color: #ffc107; background: #fffdf0; }
.finding.severity-low { border-left-color: #28a745; background: #f0fff0; }
.finding.severity-info { border-left-color: #6c757d; background: #f8f9fa; }
.finding-meta { width: auto; margin-bottom: 10px; }
.finding-meta td { border: none; padding: 3px 10px; }
.sev-critical { color: #dc3545; font-weight: bold; }
.sev-high { color: #fd7e14; font-weight: bold; }
.sev-medium { color: #d4a017; font-weight: bold; }
.sev-low { color: #28a745; }
.sev-info { color: #6c757d; }
pre.poc { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px; font-size: 9pt; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
.poc-block { margin: 10px 0; }
.asset-label { font-size: 10pt; color: #555; }
.screenshot { max-width: 100%; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
```

Create `workers/reporting_worker/renderers/executive_renderer.py`:

```python
"""Executive summary PDF renderer."""
from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from workers.reporting_worker.base_renderer import BaseRenderer
from workers.reporting_worker.models import ReportData

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class ExecutiveRenderer(BaseRenderer):
    def render_html(self, data: ReportData) -> str:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
        template = env.get_template("executive.html.j2")
        return template.render(
            company_name=data.company_name,
            base_domain=data.base_domain,
            generation_date=data.generation_date,
            summary_stats=data.summary_stats,
            finding_groups=data.finding_groups,
        )

    def render(self, data: ReportData, output_dir: str) -> list[str]:
        from weasyprint import HTML

        html_str = self.render_html(data)
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{data.company_name}_{data.generation_date}_executive.pdf"
        filepath = os.path.join(output_dir, filename)
        css_path = str(_TEMPLATES_DIR / "executive.css")
        HTML(string=html_str, base_url=str(_TEMPLATES_DIR)).write_pdf(filepath, stylesheets=[css_path])
        return [filepath]
```

Create `workers/reporting_worker/renderers/technical_renderer.py`:

```python
"""Full technical report PDF renderer."""
from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from workers.reporting_worker.base_renderer import BaseRenderer
from workers.reporting_worker.models import ReportData

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class TechnicalRenderer(BaseRenderer):
    def render_html(self, data: ReportData) -> str:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
        template = env.get_template("technical.html.j2")
        return template.render(
            company_name=data.company_name,
            base_domain=data.base_domain,
            generation_date=data.generation_date,
            summary_stats=data.summary_stats,
            finding_groups=data.finding_groups,
            assets=data.assets,
            cloud_assets=data.cloud_assets,
            api_schemas=data.api_schemas,
        )

    def render(self, data: ReportData, output_dir: str) -> list[str]:
        from weasyprint import HTML

        html_str = self.render_html(data)
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{data.company_name}_{data.generation_date}_technical.pdf"
        filepath = os.path.join(output_dir, filename)
        css_path = str(_TEMPLATES_DIR / "technical.css")
        HTML(string=html_str, base_url=str(_TEMPLATES_DIR)).write_pdf(filepath, stylesheets=[css_path])
        return [filepath]
```

Update `workers/reporting_worker/renderers/__init__.py`:

```python
from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer
from workers.reporting_worker.renderers.executive_renderer import ExecutiveRenderer
from workers.reporting_worker.renderers.technical_renderer import TechnicalRenderer

__all__ = ["MarkdownRenderer", "ExecutiveRenderer", "TechnicalRenderer"]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_pdf_renderers.py -v`
Expected: 2 HTML tests pass, 2 PDF tests skip if WeasyPrint not installed (or pass if installed).

**Step 5: Commit**

```bash
git add workers/reporting_worker/renderers/ \
       workers/reporting_worker/templates/ \
       tests/test_reporting_pdf_renderers.py
git commit -m "feat(reporting): add executive and technical PDF renderers with templates"
```

---

### Task 8: Create the pipeline

**Files:**
- Create: `workers/reporting_worker/pipeline.py`
- Test: `tests/test_reporting_pipeline.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_pipeline.py`:

```python
# tests/test_reporting_pipeline.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from lib_webbh.database import (
    Asset, Base, Location, Target, Vulnerability, get_engine, get_session,
)
from workers.reporting_worker.pipeline import Pipeline, STAGES


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_pipeline_has_four_stages():
    assert len(STAGES) == 4


def test_stage_names():
    names = [s.name for s in STAGES]
    assert names == ["data_gathering", "deduplication", "rendering", "export"]


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target_with_vuln(db):
    async with get_session() as session:
        t = Target(company_name="TestCorp", base_domain="test.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.test.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        loc = Location(asset_id=a.id, port=443, protocol="https", service="http", state="open")
        session.add(loc)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="XSS", description="Reflected XSS",
            poc="GET /search?q=<script>", source_tool="nuclei",
        )
        session.add(v)
        await session.commit()
        return t.id


@pytest.mark.anyio
async def test_pipeline_run_markdown_only(seed_target_with_vuln):
    pipeline = Pipeline()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
            result = await pipeline.run(
                target_id=seed_target_with_vuln,
                formats=["hackerone_md"],
                platform="hackerone",
                container_name="test-reporting",
                output_base=tmpdir,
            )
        assert len(result) >= 1
        assert any(f.endswith(".md") for f in result)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_pipeline.py -v`
Expected: FAIL — module not found.

**Step 3: Implement pipeline.py**

Create `workers/reporting_worker/pipeline.py`:

```python
"""Reporting pipeline: 4 sequential stages with checkpointing."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState
from lib_webbh.messaging import push_task

from workers.reporting_worker.data_gatherer import gather_report_data
from workers.reporting_worker.deduplicator import deduplicate_and_enrich
from workers.reporting_worker.renderers.executive_renderer import ExecutiveRenderer
from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer
from workers.reporting_worker.renderers.technical_renderer import TechnicalRenderer

logger = setup_logger("reporting_pipeline")


@dataclass
class Stage:
    name: str


STAGES: list[Stage] = [
    Stage("data_gathering"),
    Stage("deduplication"),
    Stage("rendering"),
    Stage("export"),
]

STAGE_INDEX: dict[str, int] = {s.name: i for i, s in enumerate(STAGES)}

FORMAT_RENDERERS = {
    "hackerone_md": MarkdownRenderer,
    "bugcrowd_md": MarkdownRenderer,
    "executive_pdf": ExecutiveRenderer,
    "technical_pdf": TechnicalRenderer,
}


class Pipeline:
    async def run(
        self,
        target_id: int,
        formats: list[str],
        platform: str,
        container_name: str,
        output_base: str = "/app/shared/reports",
    ) -> list[str]:
        log = logger.bind(target_id=target_id)
        start_index = await self._get_resume_index(target_id, container_name)
        all_output_paths: list[str] = []

        # Stage 1: Data Gathering
        if start_index <= 0:
            log.info("Starting stage", extra={"stage": "data_gathering"})
            ctx = await gather_report_data(target_id)
            await self._update_phase(target_id, container_name, "data_gathering")
            await push_task(f"events:{target_id}", {"event": "stage_complete", "stage": "data_gathering"})
        else:
            ctx = await gather_report_data(target_id)

        # Stage 2: Deduplication
        if start_index <= 1:
            log.info("Starting stage", extra={"stage": "deduplication"})
            report_data = deduplicate_and_enrich(ctx, platform=platform, formats=formats)
            await self._update_phase(target_id, container_name, "deduplication")
            await push_task(f"events:{target_id}", {"event": "stage_complete", "stage": "deduplication"})
        else:
            report_data = deduplicate_and_enrich(ctx, platform=platform, formats=formats)

        # Stage 3: Rendering
        if start_index <= 2:
            log.info("Starting stage", extra={"stage": "rendering"})
            render_dir = os.path.join(output_base, str(target_id), "_render")
            os.makedirs(render_dir, exist_ok=True)

            for fmt in formats:
                renderer_cls = FORMAT_RENDERERS.get(fmt)
                if renderer_cls is None:
                    log.warning("Unknown format, skipping", extra={"format": fmt})
                    continue
                renderer = renderer_cls()
                if fmt == "bugcrowd_md":
                    report_data.platform = "bugcrowd"
                paths = renderer.render(report_data, output_dir=render_dir)
                all_output_paths.extend(paths)
                await push_task(f"events:{target_id}", {"event": "report_format_complete", "format": fmt})
                log.info("Format rendered", extra={"format": fmt, "paths": paths})

            await self._update_phase(target_id, container_name, "rendering")

        # Stage 4: Export
        if start_index <= 3:
            log.info("Starting stage", extra={"stage": "export"})
            export_dir = os.path.join(output_base, str(target_id))
            final_paths: list[str] = []
            for src in all_output_paths:
                dst = os.path.join(export_dir, os.path.basename(src))
                if os.path.abspath(src) != os.path.abspath(dst):
                    shutil.move(src, dst)
                final_paths.append(dst)

            # Clean up temp render dir
            render_dir = os.path.join(export_dir, "_render")
            if os.path.isdir(render_dir):
                shutil.rmtree(render_dir, ignore_errors=True)

            all_output_paths = final_paths
            await self._update_phase(target_id, container_name, "export")
            await self._mark_completed(target_id, container_name)
            await push_task(f"events:{target_id}", {
                "event": "report_complete", "formats": formats,
            })

        return all_output_paths

    async def _get_resume_index(self, target_id: int, container_name: str) -> int:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row and row.current_phase and row.status != "COMPLETED":
                idx = STAGE_INDEX.get(row.current_phase, -1)
                return idx + 1
        return 0

    async def _update_phase(self, target_id: int, container_name: str, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.current_phase = phase
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self, target_id: int, container_name: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.status = "COMPLETED"
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_pipeline.py -v`
Expected: 3 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/pipeline.py tests/test_reporting_pipeline.py
git commit -m "feat(reporting): add 4-stage reporting pipeline with checkpointing"
```

---

### Task 9: Create the worker main.py entry point

**Files:**
- Create: `workers/reporting_worker/main.py`
- Test: `tests/test_reporting_main.py` (create new)

**Step 1: Write the failing test**

Create `tests/test_reporting_main.py`:

```python
# tests/test_reporting_main.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from lib_webbh.database import Base, Target, JobState, get_engine, get_session
from workers.reporting_worker.main import handle_message


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(company_name="TestCorp", base_domain="test.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.mark.anyio
async def test_handle_message_creates_job_state(seed_target):
    with patch("workers.reporting_worker.main.Pipeline") as MockPipeline:
        mock_pipeline = MockPipeline.return_value
        mock_pipeline.run = AsyncMock(return_value=["/tmp/report.md"])

        with patch("workers.reporting_worker.main.push_task", new_callable=AsyncMock):
            await handle_message("msg-1", {
                "target_id": seed_target,
                "formats": ["hackerone_md"],
                "platform": "hackerone",
            })

        async with get_session() as session:
            from sqlalchemy import select
            jobs = (await session.execute(select(JobState))).scalars().all()
            assert len(jobs) == 1
            assert jobs[0].target_id == seed_target


@pytest.mark.anyio
async def test_handle_message_nonexistent_target(db):
    with patch("workers.reporting_worker.main.Pipeline") as MockPipeline:
        with patch("workers.reporting_worker.main.push_task", new_callable=AsyncMock):
            await handle_message("msg-2", {
                "target_id": 9999,
                "formats": ["hackerone_md"],
                "platform": "hackerone",
            })
        MockPipeline.return_value.run.assert_not_called()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_main.py -v`
Expected: FAIL — module not found.

**Step 3: Implement main.py**

Create `workers/reporting_worker/main.py`:

```python
"""Reporting worker entry point."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, Target
from lib_webbh.messaging import listen_queue, push_task

from workers.reporting_worker.pipeline import Pipeline

logger = setup_logger("reporting_worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "reporting-worker-unknown")


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    while True:
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                row = (await session.execute(stmt)).scalar_one_or_none()
                if row:
                    row.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass
        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def handle_message(msg_id: str, data: dict[str, Any]) -> None:
    target_id = data["target_id"]
    formats = data.get("formats", ["hackerone_md"])
    platform = data.get("platform", "hackerone")
    container_name = get_container_name()
    log = logger.bind(target_id=target_id, container=container_name)
    log.info("Received report task", extra={"formats": formats, "platform": platform})

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            log.error("Target not found")
            return

        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        job = (await session.execute(stmt)).scalar_one_or_none()
        if job is None:
            job = JobState(
                target_id=target_id, container_name=container_name,
                status="RUNNING", current_phase="init",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.current_phase = "init"
            job.last_seen = datetime.now(timezone.utc)
        await session.commit()

    heartbeat = asyncio.create_task(_heartbeat_loop(target_id, container_name))

    try:
        pipeline = Pipeline()
        await pipeline.run(
            target_id=target_id,
            formats=formats,
            platform=platform,
            container_name=container_name,
        )
    except Exception as exc:
        log.error("Pipeline failed", extra={"error": str(exc)})
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            job = (await session.execute(stmt)).scalar_one_or_none()
            if job:
                job.status = "FAILED"
                await session.commit()
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass


async def main() -> None:
    logger.info("Reporting worker starting")
    container_name = get_container_name()
    logger.info("Listening for tasks", extra={"consumer": container_name})
    await listen_queue(
        queue="report_queue", group="reporting_group",
        consumer=container_name, callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_main.py -v`
Expected: 2 passed

**Step 5: Commit**

```bash
git add workers/reporting_worker/main.py tests/test_reporting_main.py
git commit -m "feat(reporting): add worker main.py entry point with heartbeat and job state"
```

---

### Task 10: Add orchestrator report endpoints

**Files:**
- Create: `orchestrator/routes/__init__.py` (if needed — currently routes/ doesn't exist, endpoints are inline in main.py)
- Modify: `orchestrator/main.py` — add 3 new endpoints
- Test: `tests/test_reporting_endpoints.py` (create new)

**Note:** The orchestrator currently has all endpoints inline in `main.py` (no routes/ directory). Follow the same pattern — add the new endpoints directly to `orchestrator/main.py`.

**Step 1: Write the failing test**

Create `tests/test_reporting_endpoints.py`:

```python
# tests/test_reporting_endpoints.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Vulnerability, Asset, get_engine, get_session


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target_with_vuln(db):
    async with get_session() as session:
        t = Target(company_name="ReportCorp", base_domain="report.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a = Asset(target_id=t.id, asset_type="domain", asset_value="app.report.com", source_tool="subfinder")
        session.add(a)
        await session.commit()
        await session.refresh(a)

        v = Vulnerability(
            target_id=t.id, asset_id=a.id, severity="high",
            title="Test Vuln", description="Test", poc="test poc", source_tool="test",
        )
        session.add(v)
        await session.commit()
        return t.id


@pytest_asyncio.fixture
async def seed_empty_target(db):
    async with get_session() as session:
        t = Target(company_name="EmptyCorp", base_domain="empty.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def client():
    # Patch background tasks and docker to avoid real connections
    with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock):
        with patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock):
            with patch("orchestrator.event_engine.run_redis_listener", new_callable=AsyncMock):
                from httpx import ASGITransport, AsyncClient
                from orchestrator.main import app
                transport = ASGITransport(app=app)
                return AsyncClient(transport=transport, base_url="http://test", headers={"X-API-KEY": "test-api-key-1234"})


@pytest.mark.anyio
async def test_create_report_pushes_to_queue(client, seed_target_with_vuln):
    with patch("orchestrator.main.push_task", new_callable=AsyncMock, return_value="msg-123") as mock_push:
        resp = await client.post(
            f"/api/v1/targets/{seed_target_with_vuln}/reports",
            json={"formats": ["hackerone_md"], "platform": "hackerone"},
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued"
    mock_push.assert_called_once()
    call_args = mock_push.call_args
    assert call_args[0][0] == "report_queue"


@pytest.mark.anyio
async def test_create_report_rejects_no_vulns(client, seed_empty_target):
    resp = await client.post(
        f"/api/v1/targets/{seed_empty_target}/reports",
        json={"formats": ["hackerone_md"], "platform": "hackerone"},
    )
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_create_report_rejects_unknown_target(client, db):
    resp = await client.post(
        "/api/v1/targets/9999/reports",
        json={"formats": ["hackerone_md"], "platform": "hackerone"},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_list_reports_empty(client, seed_target_with_vuln):
    with patch("orchestrator.main.SHARED_REPORTS") as mock_reports:
        mock_reports.__truediv__ = lambda self, x: tempfile.mkdtemp()
        resp = await client.get(f"/api/v1/targets/{seed_target_with_vuln}/reports")
    assert resp.status_code == 200
    assert "reports" in resp.json()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporting_endpoints.py -v`
Expected: FAIL — `push_task` call location or missing endpoints.

**Step 3: Add the endpoints to orchestrator/main.py**

Add these items to `orchestrator/main.py`:

1. Near the top config section (after `SHARED_RAW`), add:
```python
SHARED_REPORTS = Path(os.environ.get("SHARED_REPORTS_DIR", "/app/shared/reports"))
```

2. Add a new Pydantic model (after `TargetProfileUpdate`):
```python
class ReportCreate(BaseModel):
    formats: list[str] = Field(description="Report formats to generate: hackerone_md, bugcrowd_md, executive_pdf, technical_pdf")
    platform: str = Field(default="hackerone", description="Target platform: hackerone or bugcrowd")
```

3. Add three new endpoints (before the `_generate_tool_configs` function):

```python
# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/reports — trigger report generation
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/reports", status_code=201)
async def create_report(target_id: int, body: ReportCreate):
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        vuln_count = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
        )).scalars().all()
        if not vuln_count:
            raise HTTPException(status_code=400, detail="No vulnerabilities found for this target")

    msg_id = await push_task("report_queue", {
        "target_id": target_id,
        "formats": body.formats,
        "platform": body.platform,
    })

    logger.info("Report generation queued", extra={"target_id": target_id, "formats": body.formats})

    return {"job_id": msg_id, "status": "queued", "formats": body.formats}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/reports — list generated reports
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/reports")
async def list_reports(target_id: int):
    report_dir = SHARED_REPORTS / str(target_id)
    if not report_dir.is_dir():
        return {"reports": []}

    reports = []
    for f in sorted(report_dir.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            stat = f.stat()
            reports.append({
                "filename": f.name,
                "format": "pdf" if f.suffix == ".pdf" else "markdown",
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            })

    return {"reports": reports}


# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/reports/{filename} — download a report
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/reports/{filename}")
async def download_report(target_id: int, filename: str):
    from fastapi.responses import FileResponse

    # Prevent path traversal
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = SHARED_REPORTS / str(target_id) / filename
    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = "application/pdf" if filepath.suffix == ".pdf" else "text/markdown"
    return FileResponse(
        path=str(filepath),
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporting_endpoints.py -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_reporting_endpoints.py
git commit -m "feat(reporting): add report generation, listing, and download API endpoints"
```

---

### Task 11: Create Dockerfile and docker-compose entry

**Files:**
- Create: `docker/Dockerfile.reporting`
- Modify: `docker-compose.yml`
- Create: `workers/reporting_worker/requirements.txt`

**Step 1: Create requirements.txt**

Create `workers/reporting_worker/requirements.txt`:

```
jinja2>=3.1
weasyprint>=60.0
pyyaml>=6.0
markdown>=3.5
```

**Step 2: Create Dockerfile**

Create `docker/Dockerfile.reporting`:

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# System deps for asyncpg + WeasyPrint
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libpq-dev \
        libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 \
        libcairo2 libgdk-pixbuf-2.0-0 libffi-dev \
        fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

# Copy and install shared library
COPY shared/lib_webbh /app/shared/lib_webbh
RUN pip install --no-cache-dir /app/shared/lib_webbh

# Install worker dependencies
COPY workers/reporting_worker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy worker code
COPY workers/reporting_worker /app/workers/reporting_worker

# Create shared volume directories
RUN mkdir -p /app/shared/raw /app/shared/config /app/shared/logs /app/shared/reports

# Verify install
RUN python -c "from lib_webbh import Target, setup_logger; import jinja2, weasyprint; print('reporting_worker OK')"

CMD ["python", "-m", "workers.reporting_worker.main"]
```

**Step 3: Add docker-compose entry**

Add this block to `docker-compose.yml` before the `dashboard` service section:

```yaml
  # ---------------------------------------------------------------------------
  # Reporting Worker — report generation and export
  # ---------------------------------------------------------------------------
  reporting-worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.reporting
    container_name: webbh-reporting-worker
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      DB_HOST: postgres
      DB_PORT: "5432"
      DB_NAME: ${DB_NAME:-webbh}
      DB_USER: ${DB_USER:-webbh_admin}
      DB_PASS: ${DB_PASS:-changeme}
      REDIS_HOST: redis
      REDIS_PORT: "6379"
    volumes:
      - ./shared:/app/shared
    networks:
      - webbh-net
```

**Step 4: Verify docker-compose syntax**

Run: `docker compose config --quiet` (should exit 0 with no output)

**Step 5: Commit**

```bash
git add workers/reporting_worker/requirements.txt docker/Dockerfile.reporting docker-compose.yml
git commit -m "feat(reporting): add Dockerfile and docker-compose entry for reporting worker"
```

---

### Task 12: Integration test — full pipeline end-to-end

**Files:**
- Create: `tests/test_reporting_integration.py`

**Step 1: Write the integration test**

Create `tests/test_reporting_integration.py`:

```python
# tests/test_reporting_integration.py
"""End-to-end integration test for the reporting pipeline."""
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from lib_webbh.database import (
    Asset, Base, CloudAsset, Location, Observation, Target, Vulnerability,
    get_engine, get_session,
)
from workers.reporting_worker.pipeline import Pipeline


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def rich_target(db):
    """Seed a target with multiple vulns, assets, cloud assets, etc."""
    async with get_session() as session:
        t = Target(company_name="IntegCorp", base_domain="integ.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)

        a1 = Asset(target_id=t.id, asset_type="domain", asset_value="app.integ.com", source_tool="subfinder")
        a2 = Asset(target_id=t.id, asset_type="domain", asset_value="api.integ.com", source_tool="amass")
        session.add_all([a1, a2])
        await session.commit()
        await session.refresh(a1)
        await session.refresh(a2)

        session.add_all([
            Location(asset_id=a1.id, port=443, protocol="https", service="http", state="open"),
            Location(asset_id=a2.id, port=443, protocol="https", service="http", state="open"),
            Observation(asset_id=a1.id, tech_stack={"framework": "React"}, status_code=200),
        ])

        session.add_all([
            Vulnerability(target_id=t.id, asset_id=a1.id, severity="critical", title="SQL Injection",
                          description="SQLi in search", poc="GET /search?q=1' OR 1=1--", source_tool="nuclei"),
            Vulnerability(target_id=t.id, asset_id=a2.id, severity="critical", title="SQL Injection",
                          description="SQLi in API", poc="POST /api/query", source_tool="nuclei"),
            Vulnerability(target_id=t.id, asset_id=a1.id, severity="high", title="Reflected XSS",
                          description="XSS in param", poc="GET /page?x=<script>", source_tool="nuclei"),
            Vulnerability(target_id=t.id, asset_id=a1.id, severity="low", title="Missing HSTS",
                          description="No HSTS header", poc=None, source_tool="nuclei"),
        ])

        session.add(CloudAsset(target_id=t.id, provider="aws", asset_type="s3",
                                url="https://integ-backup.s3.amazonaws.com", is_public=True))
        await session.commit()
        return t.id


@pytest.mark.anyio
async def test_full_pipeline_markdown(rich_target):
    pipeline = Pipeline()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
            paths = await pipeline.run(
                target_id=rich_target,
                formats=["hackerone_md"],
                platform="hackerone",
                container_name="test-reporting-integ",
                output_base=tmpdir,
            )
    assert len(paths) == 1
    assert paths[0].endswith(".md")
    content = open(paths[0]).read()
    assert "SQL Injection" in content
    assert "Reflected XSS" in content
    assert "Missing HSTS" in content


@pytest.mark.anyio
async def test_dedup_groups_same_vuln(rich_target):
    """Two SQLi vulns on different assets should be one finding group."""
    from workers.reporting_worker.data_gatherer import gather_report_data
    from workers.reporting_worker.deduplicator import deduplicate_and_enrich

    ctx = await gather_report_data(rich_target, screenshot_base="/nonexistent")
    data = deduplicate_and_enrich(ctx, platform="hackerone", formats=["hackerone_md"])

    sqli_groups = [g for g in data.finding_groups if g.title == "SQL Injection"]
    assert len(sqli_groups) == 1
    assert len(sqli_groups[0].affected_assets) == 2


@pytest.mark.anyio
async def test_full_pipeline_multiple_formats(rich_target):
    """Test generating both markdown and PDF (PDF skipped if WeasyPrint not available)."""
    pipeline = Pipeline()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("workers.reporting_worker.pipeline.push_task", new_callable=AsyncMock):
            try:
                paths = await pipeline.run(
                    target_id=rich_target,
                    formats=["hackerone_md", "executive_pdf", "technical_pdf"],
                    platform="hackerone",
                    container_name="test-reporting-multi",
                    output_base=tmpdir,
                )
                assert any(p.endswith(".md") for p in paths)
                assert any(p.endswith(".pdf") for p in paths)
            except ImportError:
                pytest.skip("WeasyPrint not installed")
```

**Step 2: Run all tests**

Run: `pytest tests/test_reporting_*.py -v`
Expected: All reporting tests pass.

**Step 3: Commit**

```bash
git add tests/test_reporting_integration.py
git commit -m "test(reporting): add end-to-end integration test"
```

---

## Summary

| Task | Component | Files |
|------|-----------|-------|
| 1 | DB migration (cvss_score, remediation) | `database.py`, test |
| 2 | Dataclasses (models.py) | `models.py`, test |
| 3 | Remediation map + lookup | `remediation_map.yaml`, `remediation.py`, test |
| 4 | Data gatherer (Stage 1) | `data_gatherer.py`, test |
| 5 | Deduplicator (Stage 2) | `deduplicator.py`, test |
| 6 | Markdown renderer + templates | `markdown_renderer.py`, 2 templates, test |
| 7 | PDF renderers + templates | `executive_renderer.py`, `technical_renderer.py`, 6 template files, test |
| 8 | Pipeline (4 stages) | `pipeline.py`, test |
| 9 | Worker main.py | `main.py`, test |
| 10 | Orchestrator endpoints | `orchestrator/main.py` mod, test |
| 11 | Dockerfile + docker-compose | `Dockerfile.reporting`, `docker-compose.yml`, `requirements.txt` |
| 12 | Integration test | `test_reporting_integration.py` |
