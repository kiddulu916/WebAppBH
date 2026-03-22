# WebAppBH Enhancement Pack Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 25 features across backend, dashboard, performance, DevOps, and security — organized into 6 sequential batches to minimize merge conflicts and maximize incremental value.

**Architecture:** Backend-first approach. New DB models and API endpoints land first (Batch 1), then performance/reliability (Batch 2), operations tooling (Batch 3), security hardening (Batch 4), dashboard features (Batch 5), and UX polish (Batch 6). Each batch is independently deployable.

**Tech Stack:** Python 3.11 / FastAPI / SQLAlchemy 2.0 async / Redis Streams / Next.js 16 / React 19 / Zustand / Tailwind v4 / Docker Compose

---

## Batch 1: Backend Core — New Models & API Endpoints

### Task 1: New Database Models

Add 3 new tables: `bounty_submissions`, `scheduled_scans`, `scope_violations`, and a `custom_playbooks` table for user-defined playbooks.

**Files:**
- Modify: `shared/lib_webbh/database.py` — add 4 new ORM models
- Modify: `shared/lib_webbh/__init__.py` — export new models
- Test: `tests/test_database_new_models.py`

**Step 1: Write failing test**

```python
# tests/test_database_new_models.py
import pytest
from lib_webbh import BountySubmission, ScheduledScan, ScopeViolation, CustomPlaybook

pytestmark = pytest.mark.anyio

async def test_bounty_submission_create(session):
    from lib_webbh import Target, Vulnerability
    t = Target(company_name="Acme", base_domain="acme.com")
    session.add(t)
    await session.flush()
    v = Vulnerability(target_id=t.id, severity="high", title="XSS")
    session.add(v)
    await session.flush()
    b = BountySubmission(
        target_id=t.id, vulnerability_id=v.id,
        platform="hackerone", status="submitted",
        expected_payout=500.0,
    )
    session.add(b)
    await session.commit()
    assert b.id is not None
    assert b.status == "submitted"

async def test_scheduled_scan_create(session):
    from lib_webbh import Target
    t = Target(company_name="Acme", base_domain="acme.com")
    session.add(t)
    await session.flush()
    s = ScheduledScan(
        target_id=t.id, cron_expression="0 0 * * *",
        playbook="wide_recon", enabled=True,
    )
    session.add(s)
    await session.commit()
    assert s.id is not None

async def test_scope_violation_create(session):
    from lib_webbh import Target
    t = Target(company_name="Acme", base_domain="acme.com")
    session.add(t)
    await session.flush()
    sv = ScopeViolation(
        target_id=t.id, tool_name="subfinder",
        input_value="out-of-scope.com", violation_type="domain",
    )
    session.add(sv)
    await session.commit()
    assert sv.id is not None

async def test_custom_playbook_create(session):
    cp = CustomPlaybook(
        name="my_playbook", description="Custom recon",
        stages=[{"name": "passive_discovery", "enabled": True, "tool_timeout": 300}],
        concurrency={"heavy": 2, "light": 4},
    )
    session.add(cp)
    await session.commit()
    assert cp.id is not None
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_database_new_models.py -v
```

**Step 3: Implement models in `database.py`**

Add after `AssetSnapshot` class:

```python
class BountySubmission(TimestampMixin, Base):
    """Tracks vulnerability submissions to bug bounty platforms."""
    __tablename__ = "bounty_submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    vulnerability_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id"))
    platform: Mapped[str] = mapped_column(String(50))  # hackerone, bugcrowd, intigriti
    status: Mapped[str] = mapped_column(String(50))     # submitted, triaged, accepted, rejected, paid
    submission_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    expected_payout: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    actual_payout: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship()
    vulnerability: Mapped["Vulnerability"] = relationship()


class ScheduledScan(TimestampMixin, Base):
    """Cron-based recurring scan configuration."""
    __tablename__ = "scheduled_scans"
    __table_args__ = (
        UniqueConstraint("target_id", "cron_expression", name="uq_scheduled_scan_target_cron"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    cron_expression: Mapped[str] = mapped_column(String(100))
    playbook: Mapped[str] = mapped_column(String(100), default="wide_recon")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    target: Mapped["Target"] = relationship()


class ScopeViolation(TimestampMixin, Base):
    """Audit log of out-of-scope attempts."""
    __tablename__ = "scope_violations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    tool_name: Mapped[str] = mapped_column(String(100))
    input_value: Mapped[str] = mapped_column(String(2000))
    violation_type: Mapped[str] = mapped_column(String(50))  # domain, ip, cidr

    target: Mapped["Target"] = relationship()


class CustomPlaybook(TimestampMixin, Base):
    """User-defined playbook configuration."""
    __tablename__ = "custom_playbooks"
    __table_args__ = (
        UniqueConstraint("name", name="uq_custom_playbook_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stages: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    concurrency: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

Update `__init__.py` to export: `BountySubmission`, `ScheduledScan`, `ScopeViolation`, `CustomPlaybook`.

**Step 4: Run tests and verify pass**

```bash
pytest tests/test_database_new_models.py -v
```

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py shared/lib_webbh/__init__.py tests/test_database_new_models.py
git commit -m "feat: add BountySubmission, ScheduledScan, ScopeViolation, CustomPlaybook models"
```

---

### Task 2: Database Indexes

Add composite indexes on hot query paths for faster dashboard queries.

**Files:**
- Modify: `shared/lib_webbh/database.py` — add `__table_args__` indexes to existing models

**Step 1: Add indexes to existing models**

Add to `Asset.__table_args__`:
```python
__table_args__ = (
    UniqueConstraint("target_id", "asset_type", "asset_value", name="uq_assets_target_type_value"),
    Index("ix_assets_target_type", "target_id", "asset_type"),
    Index("ix_assets_target_created", "target_id", "created_at"),
)
```

Add to `Vulnerability`:
```python
__table_args__ = (
    Index("ix_vulns_target_severity", "target_id", "severity"),
    Index("ix_vulns_target_created", "target_id", "created_at"),
)
```

Add to `Alert`:
```python
__table_args__ = (
    Index("ix_alerts_target_read", "target_id", "is_read"),
)
```

Add to `JobState`:
```python
__table_args__ = (
    Index("ix_jobstate_target_status", "target_id", "status"),
    Index("ix_jobstate_container_status", "container_name", "status"),
)
```

Need to import `Index` from `sqlalchemy`.

**Step 2: Test that tables still create correctly**

```bash
pytest tests/test_database.py -v
```

**Step 3: Commit**

```bash
git add shared/lib_webbh/database.py
git commit -m "perf: add composite indexes on assets, vulns, alerts, job_state"
```

---

### Task 3: Bounty Tracker API

CRUD endpoints for tracking vulnerability submissions to bug bounty platforms.

**Files:**
- Modify: `orchestrator/main.py` — add 4 endpoints
- Test: `tests/test_bounty_tracker.py`

**Endpoints:**

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/bounties` | Create submission |
| GET | `/api/v1/bounties` | List submissions (filter by target_id, status) |
| PATCH | `/api/v1/bounties/{id}` | Update status/payout |
| GET | `/api/v1/bounties/stats` | ROI stats per target |

**Pydantic models:**

```python
class BountyCreate(BaseModel):
    target_id: int
    vulnerability_id: int
    platform: str = Field(description="hackerone, bugcrowd, intigriti")
    status: str = Field(default="submitted")
    submission_url: Optional[str] = None
    expected_payout: Optional[float] = None
    notes: Optional[str] = None

class BountyUpdate(BaseModel):
    status: Optional[str] = None
    actual_payout: Optional[float] = None
    submission_url: Optional[str] = None
    notes: Optional[str] = None
```

**Stats endpoint returns:**

```json
{
  "stats": {
    "total_submitted": 15,
    "total_accepted": 8,
    "total_paid": 5,
    "total_payout": 12500.0,
    "by_platform": { "hackerone": { "count": 10, "payout": 8000.0 } },
    "by_target": { "1": { "count": 5, "payout": 3000.0 } }
  }
}
```

**Test file structure:**

```python
# tests/test_bounty_tracker.py
import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app

pytestmark = pytest.mark.anyio

@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

async def test_create_bounty(client, seed_target_with_vuln):
    target_id, vuln_id = seed_target_with_vuln
    res = await client.post("/api/v1/bounties", json={
        "target_id": target_id, "vulnerability_id": vuln_id,
        "platform": "hackerone", "expected_payout": 500.0,
    })
    assert res.status_code == 201
    assert res.json()["platform"] == "hackerone"

async def test_list_bounties(client, seed_target_with_vuln):
    target_id, _ = seed_target_with_vuln
    res = await client.get(f"/api/v1/bounties?target_id={target_id}")
    assert res.status_code == 200
    assert "bounties" in res.json()

async def test_update_bounty_status(client, seed_bounty):
    bounty_id = seed_bounty
    res = await client.patch(f"/api/v1/bounties/{bounty_id}", json={
        "status": "accepted", "actual_payout": 750.0,
    })
    assert res.status_code == 200
    assert res.json()["status"] == "accepted"

async def test_bounty_stats(client, seed_bounties_with_payouts):
    res = await client.get("/api/v1/bounties/stats")
    assert res.status_code == 200
    assert res.json()["stats"]["total_payout"] > 0
```

**Step 1:** Write test file with fixtures
**Step 2:** Run tests to verify they fail
**Step 3:** Implement 4 endpoints in `orchestrator/main.py`
**Step 4:** Run tests to verify pass
**Step 5:** Commit

---

### Task 4: Target Scheduling API

Cron-based recurring scan management. The orchestrator's event engine checks `scheduled_scans` on each heartbeat cycle and triggers rescans when `next_run_at` passes.

**Files:**
- Modify: `orchestrator/main.py` — add 4 endpoints
- Modify: `orchestrator/event_engine.py` — add `_check_scheduled_scans()` to heartbeat
- Create: `shared/lib_webbh/cron_utils.py` — cron expression parser (use `croniter` library)
- Test: `tests/test_scheduling.py`

**Endpoints:**

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/schedules` | Create schedule |
| GET | `/api/v1/schedules` | List schedules (filter by target_id) |
| PATCH | `/api/v1/schedules/{id}` | Enable/disable/update cron |
| DELETE | `/api/v1/schedules/{id}` | Remove schedule |

**Cron utilities (`cron_utils.py`):**

```python
from croniter import croniter
from datetime import datetime, timezone

def next_run(cron_expression: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return croniter(cron_expression, now).get_next(datetime)

def is_valid_cron(expression: str) -> bool:
    try:
        croniter(expression)
        return True
    except (ValueError, KeyError):
        return False
```

**Event engine integration:**

Add to `_heartbeat_cycle()` body (at the end):

```python
await _check_scheduled_scans()
```

```python
async def _check_scheduled_scans() -> None:
    """Trigger rescans for scheduled scans whose next_run_at has passed."""
    from lib_webbh import ScheduledScan
    from lib_webbh.cron_utils import next_run

    now = datetime.now(timezone.utc)
    async with get_session() as session:
        stmt = select(ScheduledScan).where(
            ScheduledScan.enabled == True,
            ScheduledScan.next_run_at <= now,
        )
        result = await session.execute(stmt)
        due = result.scalars().all()

    for scan in due:
        logger.info("Scheduled scan triggered", extra={
            "target_id": scan.target_id, "cron": scan.cron_expression,
        })
        await push_task("recon_queue", {
            "target_id": scan.target_id, "rescan": True,
            "scheduled": True, "playbook": scan.playbook,
        })
        # Update last_run_at and next_run_at
        async with get_session() as session:
            stmt_update = (
                update(ScheduledScan)
                .where(ScheduledScan.id == scan.id)
                .values(last_run_at=now, next_run_at=next_run(scan.cron_expression, now))
            )
            await session.execute(stmt_update)
            await session.commit()
```

**Dependencies:** Add `croniter` to `shared/lib_webbh/pyproject.toml` or `setup.cfg`.

**Step 1:** Write tests
**Step 2:** Install croniter, implement `cron_utils.py`
**Step 3:** Implement endpoints
**Step 4:** Add `_check_scheduled_scans()` to event engine
**Step 5:** Run tests, commit

---

### Task 5: Target Intel Enrichment — Shodan + SecurityTrails

Add a pre-recon intel enrichment stage that queries Shodan and SecurityTrails APIs. Check for API keys in env; if missing, the ScopeBuilder UI will prompt the user.

**Files:**
- Create: `shared/lib_webbh/intel_enrichment.py` — Shodan + SecurityTrails API clients
- Modify: `orchestrator/main.py` — add `POST /api/v1/targets/{id}/enrich` endpoint
- Modify: `orchestrator/main.py` — add `GET /api/v1/config/api_keys` to check which keys are set
- Modify: `orchestrator/main.py` — add `PUT /api/v1/config/api_keys` to save keys to env file
- Modify: `docker-compose.yml` — add `SHODAN_API_KEY` and `SECURITYTRAILS_API_KEY` env vars
- Modify: `shared/setup_env.py` — add new env var placeholders
- Test: `tests/test_intel_enrichment.py`

**Intel enrichment module (`intel_enrichment.py`):**

```python
"""Passive OSINT enrichment via Shodan and SecurityTrails."""
from __future__ import annotations

import os
import httpx
from dataclasses import dataclass

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")


@dataclass
class IntelResult:
    source: str
    subdomains: list[str]
    ips: list[str]
    ports: list[dict]  # {"ip": ..., "port": ..., "service": ...}
    raw: dict


async def enrich_shodan(domain: str) -> IntelResult:
    """Query Shodan for host data related to the domain."""
    if not SHODAN_API_KEY:
        return IntelResult(source="shodan", subdomains=[], ips=[], ports=[], raw={"error": "no_api_key"})

    async with httpx.AsyncClient(timeout=30) as client:
        # DNS resolve
        dns_res = await client.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": SHODAN_API_KEY},
        )
        dns_data = dns_res.json() if dns_res.status_code == 200 else {}

        subdomains = [
            f"{sub}.{domain}"
            for sub in dns_data.get("subdomains", [])
        ]

        # Host search
        search_res = await client.get(
            f"https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_API_KEY, "query": f"hostname:{domain}"},
        )
        search_data = search_res.json() if search_res.status_code == 200 else {}

        ips = list({m["ip_str"] for m in search_data.get("matches", [])})
        ports = [
            {"ip": m["ip_str"], "port": m["port"], "service": m.get("product", "")}
            for m in search_data.get("matches", [])
        ]

    return IntelResult(source="shodan", subdomains=subdomains, ips=ips, ports=ports, raw=search_data)


async def enrich_securitytrails(domain: str) -> IntelResult:
    """Query SecurityTrails for subdomain and DNS data."""
    if not SECURITYTRAILS_API_KEY:
        return IntelResult(source="securitytrails", subdomains=[], ips=[], ports=[], raw={"error": "no_api_key"})

    headers = {"APIKEY": SECURITYTRAILS_API_KEY, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        # Subdomains
        sub_res = await client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        )
        sub_data = sub_res.json() if sub_res.status_code == 200 else {}
        subdomains = [
            f"{sub}.{domain}"
            for sub in sub_data.get("subdomains", [])
        ]

        # DNS history for A records → IPs
        dns_res = await client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}",
        )
        dns_data = dns_res.json() if dns_res.status_code == 200 else {}
        current = dns_data.get("current_dns", {}).get("a", {})
        ips = [r.get("ip", "") for r in current.get("values", []) if r.get("ip")]

    return IntelResult(source="securitytrails", subdomains=subdomains, ips=ips, ports=[], raw=dns_data)


def get_available_intel_sources() -> dict[str, bool]:
    """Return which intel API keys are configured."""
    return {
        "shodan": bool(SHODAN_API_KEY),
        "securitytrails": bool(SECURITYTRAILS_API_KEY),
    }
```

**API key management endpoints:**

```python
# GET /api/v1/config/api_keys — check which keys are set (no values exposed)
@app.get("/api/v1/config/api_keys")
async def get_api_key_status():
    from lib_webbh.intel_enrichment import get_available_intel_sources
    return {"keys": get_available_intel_sources()}

# PUT /api/v1/config/api_keys — save keys to shared config env file
class ApiKeyUpdate(BaseModel):
    shodan_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None

@app.put("/api/v1/config/api_keys")
async def update_api_keys(body: ApiKeyUpdate):
    import lib_webbh.intel_enrichment as ie
    env_path = SHARED_CONFIG / ".env.intel"
    lines = []
    if body.shodan_api_key is not None:
        os.environ["SHODAN_API_KEY"] = body.shodan_api_key
        ie.SHODAN_API_KEY = body.shodan_api_key
        lines.append(f"SHODAN_API_KEY={body.shodan_api_key}")
    if body.securitytrails_api_key is not None:
        os.environ["SECURITYTRAILS_API_KEY"] = body.securitytrails_api_key
        ie.SECURITYTRAILS_API_KEY = body.securitytrails_api_key
        lines.append(f"SECURITYTRAILS_API_KEY={body.securitytrails_api_key}")
    if lines:
        env_path.write_text("\n".join(lines) + "\n")
    return {"keys": ie.get_available_intel_sources()}
```

**Enrich endpoint:**

```python
# POST /api/v1/targets/{target_id}/enrich
@app.post("/api/v1/targets/{target_id}/enrich")
async def enrich_target(target_id: int):
    from lib_webbh.intel_enrichment import enrich_shodan, enrich_securitytrails
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

    results = []
    for enricher in [enrich_shodan, enrich_securitytrails]:
        result = await enricher(target.base_domain)
        results.append({"source": result.source, "subdomains": len(result.subdomains), "ips": len(result.ips), "ports": len(result.ports)})
        # Seed assets into DB
        async with get_session() as session:
            for sub in result.subdomains:
                existing = (await session.execute(
                    select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_type == "subdomain",
                        Asset.asset_value == sub,
                    )
                )).scalar_one_or_none()
                if not existing:
                    session.add(Asset(target_id=target_id, asset_type="subdomain", asset_value=sub, source_tool=result.source))
            for ip in result.ips:
                existing = (await session.execute(
                    select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_type == "ip",
                        Asset.asset_value == ip,
                    )
                )).scalar_one_or_none()
                if not existing:
                    session.add(Asset(target_id=target_id, asset_type="ip", asset_value=ip, source_tool=result.source))
            await session.commit()

    return {"target_id": target_id, "enrichment": results}
```

**Docker-compose env vars to add to orchestrator service:**

```yaml
SHODAN_API_KEY: ${SHODAN_API_KEY:-}
SECURITYTRAILS_API_KEY: ${SECURITYTRAILS_API_KEY:-}
```

**Step 1:** Write tests (mock httpx calls)
**Step 2:** Create `intel_enrichment.py`
**Step 3:** Add endpoints to `main.py`
**Step 4:** Update `docker-compose.yml` and `setup_env.py`
**Step 5:** Run tests, commit

---

### Task 6: Custom Playbook CRUD API

Allow users to create, list, update, and delete custom playbooks that supplement the 4 built-in ones. Modify `get_playbook()` to check custom playbooks too.

**Files:**
- Modify: `orchestrator/main.py` — add 4 endpoints
- Modify: `shared/lib_webbh/playbooks.py` — modify `get_playbook()` to check DB
- Test: `tests/test_custom_playbooks.py`

**Endpoints:**

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/playbooks` | Create custom playbook |
| GET | `/api/v1/playbooks` | List all playbooks (built-in + custom) |
| PATCH | `/api/v1/playbooks/{id}` | Update custom playbook |
| DELETE | `/api/v1/playbooks/{id}` | Delete custom playbook |

**Pydantic models:**

```python
class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    stages: list[dict] = Field(description="List of {name, enabled, tool_timeout}")
    concurrency: dict = Field(default={"heavy": 2, "light": 4})

class PlaybookUpdate(BaseModel):
    description: Optional[str] = None
    stages: Optional[list[dict]] = None
    concurrency: Optional[dict] = None
```

**Step 1:** Write tests
**Step 2:** Implement endpoints + modify `get_playbook()`
**Step 3:** Run tests, commit

---

### Task 7: Findings Export API

Export vulnerabilities as CSV, JSON, or Markdown from a single endpoint.

**Files:**
- Modify: `orchestrator/main.py` — add `GET /api/v1/targets/{id}/export`
- Test: `tests/test_export.py`

**Endpoint:**

```python
@app.get("/api/v1/targets/{target_id}/export")
async def export_findings(
    target_id: int,
    format: str = Query(default="json", description="json, csv, or markdown"),
):
```

- `json` → returns `{"vulnerabilities": [...]}`
- `csv` → returns `text/csv` with headers: id, severity, title, asset, source_tool, cvss, created_at
- `markdown` → returns `text/markdown` with a table

**Step 1:** Write tests for each format
**Step 2:** Implement endpoint with `StreamingResponse` for CSV/MD
**Step 3:** Run tests, commit

---

### Task 8: Scope Violation Audit Log

Persist scope violations to DB instead of just logging. Modify `ScopeManager` to accept an optional callback, and add an API endpoint to query violations.

**Files:**
- Modify: `shared/lib_webbh/scope.py` — add `on_violation` callback parameter
- Modify: `orchestrator/main.py` — add `GET /api/v1/scope_violations`
- Test: `tests/test_scope_violations.py`

**Endpoint:**

```python
@app.get("/api/v1/scope_violations")
async def list_scope_violations(
    target_id: int = Query(...),
    limit: int = Query(default=100, le=500),
):
    from lib_webbh import ScopeViolation
    async with get_session() as session:
        stmt = (
            select(ScopeViolation)
            .where(ScopeViolation.target_id == target_id)
            .order_by(ScopeViolation.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        violations = result.scalars().all()
    return {"violations": [
        {"id": v.id, "tool_name": v.tool_name, "input_value": v.input_value,
         "violation_type": v.violation_type, "created_at": v.created_at.isoformat()}
        for v in violations
    ]}
```

**Step 1:** Write test
**Step 2:** Implement endpoint
**Step 3:** Commit

---

### Task 9: Input Validation Hardening

Add field constraints to all existing Pydantic models.

**Files:**
- Modify: `orchestrator/main.py` — add `Field()` constraints

**Changes:**

```python
class TargetCreate(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=255)
    base_domain: str = Field(..., min_length=3, max_length=255, pattern=r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$')
    target_profile: Optional[dict] = None
    playbook: str = Field(default="wide_recon", pattern=r'^[a-z_]+$')

class ControlAction(BaseModel):
    container_name: str = Field(..., min_length=1, max_length=100, pattern=r'^webbh-')
    action: str = Field(..., pattern=r'^(pause|stop|restart|unpause)$')

class ReportCreate(BaseModel):
    formats: list[Literal["hackerone_md", "bugcrowd_md", "executive_pdf", "technical_pdf"]] = Field(..., min_length=1)
    platform: Literal["hackerone", "bugcrowd"] = "hackerone"
```

**Step 1:** Update models
**Step 2:** Write test for invalid input rejection (empty strings, invalid patterns)
**Step 3:** Run existing tests to verify no regressions
**Step 4:** Commit

---

### Task 10: API Rate Limiting

Add per-endpoint rate limiting using a Redis-backed sliding window.

**Files:**
- Create: `orchestrator/rate_limit.py` — rate limit middleware
- Modify: `orchestrator/main.py` — apply middleware

**Rate limiter implementation:**

```python
"""Redis-backed sliding window rate limiter."""
from __future__ import annotations

import time
from fastapi import Request, HTTPException
from lib_webbh.messaging import get_redis

# Defaults: 60 requests per minute for mutating, 200 for reads
RATE_LIMITS = {
    "POST": {"window": 60, "max_requests": 60},
    "PATCH": {"window": 60, "max_requests": 60},
    "PUT": {"window": 60, "max_requests": 60},
    "DELETE": {"window": 60, "max_requests": 60},
    "GET": {"window": 60, "max_requests": 200},
}

async def rate_limit_check(request: Request) -> None:
    """Check rate limit for the current request. Raises 429 if exceeded."""
    method = request.method
    config = RATE_LIMITS.get(method)
    if not config:
        return

    client_ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:{client_ip}:{method}"
    now = time.time()
    window = config["window"]
    max_req = config["max_requests"]

    redis = get_redis()
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, now - window)
    pipe.zadd(key, {str(now): now})
    pipe.zcard(key)
    pipe.expire(key, window)
    results = await pipe.execute()
    count = results[2]

    if count > max_req:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {max_req} requests per {window}s",
        )
```

Apply as middleware in `main.py`:

```python
from orchestrator.rate_limit import rate_limit_check

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    await rate_limit_check(request)
    return await call_next(request)
```

**Step 1:** Write test for rate limiting (send > limit requests)
**Step 2:** Implement rate_limit.py
**Step 3:** Add middleware to main.py
**Step 4:** Run tests, commit

---

## Batch 2: Performance & Reliability

### Task 11: Worker Result Batching

Add batch insert support to reduce DB round-trips in workers.

**Files:**
- Create: `shared/lib_webbh/batch_insert.py` — batched DB insert utility
- Test: `tests/test_batch_insert.py`

**Implementation:**

```python
"""Batched async DB inserts with configurable flush interval."""
from __future__ import annotations

import asyncio
from typing import Any
from sqlalchemy.dialects.postgresql import insert as pg_insert
from lib_webbh.database import get_session, Base

class BatchInserter:
    def __init__(self, model: type[Base], batch_size: int = 50, flush_interval: float = 2.0):
        self.model = model
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None

    async def add(self, data: dict[str, Any]) -> None:
        async with self._lock:
            self._buffer.append(data)
            if len(self._buffer) >= self.batch_size:
                await self._flush_locked()
            elif self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(self._timed_flush())

    async def _timed_flush(self) -> None:
        await asyncio.sleep(self.flush_interval)
        async with self._lock:
            if self._buffer:
                await self._flush_locked()

    async def _flush_locked(self) -> None:
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()
        async with get_session() as session:
            stmt = pg_insert(self.model.__table__).values(batch)
            stmt = stmt.on_conflict_do_nothing()
            await session.execute(stmt)
            await session.commit()

    async def flush(self) -> None:
        async with self._lock:
            await self._flush_locked()
```

**Step 1:** Write tests
**Step 2:** Implement
**Step 3:** Commit

---

### Task 12: SSE Reconnection with Last-Event-ID Replay

Modify the SSE endpoint to support `Last-Event-ID` header for replay on reconnect.

**Files:**
- Modify: `orchestrator/main.py` — update `stream_events` endpoint

**Changes to `stream_events`:**

```python
@app.get("/api/v1/stream/{target_id}")
async def stream_events(target_id: int, request: Request):
    queue = f"events:{target_id}"
    group = "sse_consumers"
    consumer = f"sse-{uuid4().hex}"

    redis = get_redis()
    try:
        await redis.xgroup_create(queue, group, id="0", mkstream=True)
    except Exception:
        pass

    # Support Last-Event-ID for replay
    last_event_id = request.headers.get("Last-Event-ID")
    start_id = last_event_id if last_event_id else ">"

    async def _generate():
        read_id = start_id
        try:
            # If replaying, first catch up from the specific ID
            if read_id != ">":
                # Read missed messages from the stream directly (not consumer group)
                messages = await redis.xrange(queue, min=read_id, count=100)
                for msg_id, data in messages:
                    if msg_id == read_id:
                        continue  # skip the one we already have
                    payload = json.loads(data.get("payload", "{}"))
                    event_type = payload.get("event", "message")
                    yield {"event": event_type, "data": json.dumps(payload), "id": msg_id}
                read_id = ">"

            while True:
                if await request.is_disconnected():
                    break
                messages = await redis.xreadgroup(
                    groupname=group, consumername=consumer,
                    streams={queue: read_id}, count=10, block=2000,
                )
                for _, entries in messages:
                    for msg_id, data in entries:
                        payload = json.loads(data.get("payload", "{}"))
                        event_type = payload.get("event", "message")
                        yield {"event": event_type, "data": json.dumps(payload), "id": msg_id}
                        await redis.xack(queue, group, msg_id)
        finally:
            try:
                await redis.xautoclaim(queue, group, consumer, min_idle_time=0)
            except Exception:
                pass

    return EventSourceResponse(_generate())
```

**Dashboard side** — update `useEventStream.ts` to store `lastEventId`:

The browser's native `EventSource` automatically sends `Last-Event-ID` on reconnect when the server sends `id:` fields in SSE events. No dashboard code change needed beyond ensuring the hook uses `EventSource` (which it already does).

**Step 1:** Write test that simulates disconnect/reconnect
**Step 2:** Update endpoint
**Step 3:** Commit

---

### Task 13: Connection Pool Tuning

Make pool parameters configurable via environment variables.

**Files:**
- Modify: `shared/lib_webbh/database.py` — read pool config from env
- Modify: `shared/lib_webbh/messaging.py` — add Redis connection pool config

**Database changes:**

```python
def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url = _build_url()
        kwargs: dict = {}
        if not url.startswith("sqlite"):
            kwargs.update(
                pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
                max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
                pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", "3600")),
                pool_pre_ping=True,
            )
        _engine = create_async_engine(url, **kwargs)
    return _engine
```

**Redis changes:**

```python
def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        host = os.environ.get("REDIS_HOST", "localhost")
        port = int(os.environ.get("REDIS_PORT", "6379"))
        max_connections = int(os.environ.get("REDIS_MAX_CONNECTIONS", "50"))
        _redis = aioredis.Redis(
            host=host, port=port, decode_responses=True,
            max_connections=max_connections,
        )
    return _redis
```

**Step 1:** Update code
**Step 2:** Run existing tests
**Step 3:** Commit

---

### Task 14: Worker Crash Recovery with Exponential Backoff

Improve the zombie handler to use exponential backoff instead of fixed retry.

**Files:**
- Modify: `orchestrator/event_engine.py` — update `_handle_zombie()`

**Changes:**

Replace the fixed retry logic with exponential backoff:

```python
async def _handle_zombie(job: JobState, now: datetime) -> None:
    logger.warning("ZOMBIE_RESTART — killing unresponsive job",
                    extra={"container": job.container_name, "last_seen": str(job.last_seen)})
    await worker_manager.kill_worker(job.container_name)

    async with get_session() as session:
        stmt = update(JobState).where(JobState.id == job.id).values(status="FAILED", last_seen=now)
        await session.execute(stmt)

        retry_stmt = (
            select(func.count(Alert.id))
            .where(
                Alert.target_id == job.target_id,
                Alert.alert_type == "ZOMBIE_RESTART",
                Alert.message.like(f"%{job.container_name}%"),
            )
        )
        result = await session.execute(retry_stmt)
        retry_count = result.scalar() or 0

        if retry_count >= ZOMBIE_MAX_RETRIES:
            session.add(Alert(
                target_id=job.target_id, alert_type="CRITICAL_ALERT",
                message=f"Container {job.container_name} exceeded {ZOMBIE_MAX_RETRIES} zombie restarts. Permanently failed.",
            ))
        else:
            # Exponential backoff: 30s, 60s, 120s, ...
            backoff_seconds = 30 * (2 ** retry_count)
            session.add(Alert(
                target_id=job.target_id, alert_type="ZOMBIE_RESTART",
                message=f"Container {job.container_name} unresponsive. Retry {retry_count + 1}/{ZOMBIE_MAX_RETRIES} after {backoff_seconds}s backoff.",
            ))
        await session.commit()

    if retry_count >= ZOMBIE_MAX_RETRIES:
        await _emit_event(job.target_id, "CRITICAL_ALERT", {
            "container": job.container_name,
            "message": f"Exceeded {ZOMBIE_MAX_RETRIES} zombie restarts",
        })
    else:
        # Schedule delayed restart
        backoff_seconds = 30 * (2 ** retry_count)
        asyncio.get_event_loop().call_later(
            backoff_seconds,
            lambda: asyncio.create_task(_delayed_restart(job)),
        )

async def _delayed_restart(job: JobState) -> None:
    parts = job.container_name.replace("webbh-", "").rsplit("-t", 1)
    worker_key = parts[0] if parts else None
    if worker_key and worker_key in WORKER_IMAGES:
        await _trigger_worker(job.target_id, worker_key, job.current_phase or worker_key)
```

**Step 1:** Implement changes
**Step 2:** Run existing event engine tests
**Step 3:** Commit

---

## Batch 3: Operations & DevOps

### Task 15: Prometheus Metrics Endpoint

Expose `/metrics` on the orchestrator with key operational metrics.

**Files:**
- Create: `orchestrator/metrics.py` — Prometheus metrics
- Modify: `orchestrator/main.py` — mount metrics endpoint
- Add dependency: `prometheus-client` or `prometheus-fastapi-instrumentator`

**Implementation using `prometheus-client`:**

```python
# orchestrator/metrics.py
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

# Counters
targets_created = Counter("webbh_targets_created_total", "Total targets created")
vulns_found = Counter("webbh_vulns_found_total", "Total vulns discovered", ["severity"])
scans_triggered = Counter("webbh_scans_triggered_total", "Scans triggered", ["type"])

# Gauges
active_workers = Gauge("webbh_active_workers", "Currently running workers")
queue_depth = Gauge("webbh_queue_depth", "Pending messages per queue", ["queue"])
connected_sse_clients = Gauge("webbh_sse_clients", "Connected SSE clients")

# Histograms
api_latency = Histogram("webbh_api_latency_seconds", "API request latency", ["method", "endpoint"])

def metrics_endpoint():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

Add to `main.py`:

```python
from orchestrator.metrics import metrics_endpoint
app.get("/metrics", include_in_schema=False)(lambda: metrics_endpoint())
```

Increment counters at appropriate call sites (target creation, vuln discovery events, etc.).

**Step 1:** Install `prometheus-client`
**Step 2:** Create `metrics.py`
**Step 3:** Wire into `main.py` and event engine
**Step 4:** Commit

---

### Task 16: Centralized Structured Logging with Correlation IDs

Add correlation IDs to requests that propagate across orchestrator → Redis → workers.

**Files:**
- Modify: `shared/lib_webbh/logger.py` — add correlation ID support
- Modify: `orchestrator/main.py` — add middleware to inject correlation ID
- Modify: `shared/lib_webbh/messaging.py` — include correlation ID in messages

**Middleware:**

```python
import uuid
from starlette.middleware.base import BaseHTTPMiddleware

class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", uuid.uuid4().hex)
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
```

**Messaging change** — add `correlation_id` field to `push_task`:

```python
async def push_task(queue: str, data: dict[str, Any], correlation_id: str | None = None) -> str:
    r = get_redis()
    if correlation_id:
        data["_correlation_id"] = correlation_id
    payload = json.dumps(data, default=str)
    timestamp = datetime.now(timezone.utc).isoformat()
    msg_id: str = await r.xadd(queue, {"payload": payload, "timestamp": timestamp})
    return msg_id
```

**Step 1:** Implement middleware
**Step 2:** Update messaging
**Step 3:** Run tests
**Step 4:** Commit

---

### Task 17: Backup/Restore CLI

A simple Python script for `pg_dump`-based backup and restore of target data.

**Files:**
- Create: `scripts/backup.py` — backup script
- Create: `scripts/restore.py` — restore script

**Backup script:**

```python
#!/usr/bin/env python3
"""Backup WebAppBH database and config files."""
import os, subprocess, shutil, sys
from datetime import datetime

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "webbh")
DB_USER = os.environ.get("DB_USER", "webbh_admin")

def backup(output_dir: str = "backups"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(output_dir, f"webbh_backup_{ts}")
    os.makedirs(backup_dir, exist_ok=True)

    # pg_dump
    dump_file = os.path.join(backup_dir, "database.sql")
    cmd = [
        "pg_dump", "-h", DB_HOST, "-p", DB_PORT, "-U", DB_USER,
        "-d", DB_NAME, "-f", dump_file, "--no-owner", "--no-privileges",
    ]
    subprocess.run(cmd, check=True, env={**os.environ, "PGPASSWORD": os.environ.get("DB_PASS", "")})

    # Copy shared config
    config_src = os.environ.get("SHARED_CONFIG_DIR", "shared/config")
    if os.path.isdir(config_src):
        shutil.copytree(config_src, os.path.join(backup_dir, "config"))

    print(f"Backup saved to: {backup_dir}")
    return backup_dir

if __name__ == "__main__":
    backup(sys.argv[1] if len(sys.argv) > 1 else "backups")
```

**Restore script** follows same pattern with `psql` for restore.

**Step 1:** Create scripts
**Step 2:** Test locally
**Step 3:** Commit

---

### Task 18: Docker Image Optimization

Add multi-stage builds to reduce worker image sizes.

**Files:**
- Modify: `docker/Dockerfile.base` — add multi-stage build
- Modify worker Dockerfiles as needed

**Pattern:**

```dockerfile
# Build stage
FROM python:3.11-slim AS builder
WORKDIR /build
COPY shared/lib_webbh/ ./shared/lib_webbh/
RUN pip install --no-cache-dir --target=/install ./shared/lib_webbh

# Runtime stage
FROM python:3.11-slim
COPY --from=builder /install /usr/local/lib/python3.11/site-packages/
WORKDIR /app
COPY workers/recon_core/ ./workers/recon_core/
```

**Step 1:** Update Dockerfile.base
**Step 2:** Test build: `docker compose build`
**Step 3:** Compare image sizes (before/after)
**Step 4:** Commit

---

### Task 19: Integration Test Suite

Docker-compose-based end-to-end test: create target → verify assets in DB → check SSE events.

**Files:**
- Create: `tests/integration/test_e2e_pipeline.py`
- Create: `tests/integration/docker-compose.test.yml` — test-specific compose

**Test structure:**

```python
# tests/integration/test_e2e_pipeline.py
"""End-to-end integration test (requires running services)."""
import os, pytest, httpx, asyncio

BASE_URL = os.environ.get("TEST_API_URL", "http://localhost:8001")
API_KEY = os.environ.get("WEB_APP_BH_API_KEY", "")

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

@pytest.fixture
async def client():
    async with httpx.AsyncClient(
        base_url=BASE_URL,
        headers={"X-API-KEY": API_KEY, "Content-Type": "application/json"},
        timeout=30,
    ) as c:
        yield c

async def test_create_target_and_check_status(client):
    res = await client.post("/api/v1/targets", json={
        "company_name": "IntegrationTest",
        "base_domain": "example-integration.com",
        "playbook": "wide_recon",
    })
    assert res.status_code == 201
    target_id = res.json()["target_id"]

    # Verify target appears in list
    targets = await client.get("/api/v1/targets")
    assert any(t["id"] == target_id for t in targets.json()["targets"])

    # Verify status endpoint works
    status = await client.get(f"/api/v1/status?target_id={target_id}")
    assert status.status_code == 200

async def test_sse_connection(client):
    res = await client.post("/api/v1/targets", json={
        "company_name": "SSETest", "base_domain": "sse-test.com",
    })
    target_id = res.json()["target_id"]
    # Just verify the SSE endpoint responds
    async with httpx.AsyncClient(base_url=BASE_URL, headers={"X-API-KEY": API_KEY}) as c:
        async with c.stream("GET", f"/api/v1/stream/{target_id}") as stream:
            assert stream.status_code == 200
            break  # just check connection
```

**Step 1:** Create test file
**Step 2:** Create test compose file
**Step 3:** Add `pytest -m integration` to makefile/scripts
**Step 4:** Commit

---

### Task 20: Secret Scanning in Results

Auto-detect leaked API keys/tokens in tool output and escalate to CRITICAL.

**Files:**
- Create: `shared/lib_webbh/secret_scanner.py` — regex-based secret detection
- Test: `tests/test_secret_scanner.py`

**Implementation:**

```python
"""Detect leaked secrets in tool output."""
from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass
class SecretMatch:
    pattern_name: str
    matched_value: str
    line_number: int

PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}'),
    "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),
    "generic_api_key": re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9]{20,}'),
    "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "stripe_key": re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
    "heroku_api_key": re.compile(r'(?i)heroku.*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
}

def scan_text(text: str) -> list[SecretMatch]:
    """Scan text for potential secrets. Returns list of matches."""
    matches = []
    for line_num, line in enumerate(text.split("\n"), 1):
        for name, pattern in PATTERNS.items():
            for m in pattern.finditer(line):
                # Redact most of the matched value
                val = m.group()
                redacted = val[:8] + "..." + val[-4:] if len(val) > 16 else val[:4] + "..."
                matches.append(SecretMatch(
                    pattern_name=name, matched_value=redacted, line_number=line_num,
                ))
    return matches
```

Workers can call `scan_text()` on tool stdout and auto-create a CRITICAL vuln if secrets are found.

**Step 1:** Write tests with known secret patterns
**Step 2:** Implement
**Step 3:** Commit

---

## Batch 4: Dashboard — API Client & State Updates

### Task 21: Dashboard API Client Updates

Add all new API endpoints to the dashboard's `api.ts` client.

**Files:**
- Modify: `dashboard/src/lib/api.ts` — add new methods

**New methods to add:**

```typescript
// Bounty Tracker
createBounty(data: { target_id: number; vulnerability_id: number; platform: string; expected_payout?: number }) {
  return request<any>("/api/v1/bounties", { method: "POST", body: JSON.stringify(data) });
},
getBounties(targetId: number, status?: string) {
  let qs = `?target_id=${targetId}`;
  if (status) qs += `&status=${status}`;
  return request<{ bounties: any[] }>(`/api/v1/bounties${qs}`);
},
updateBounty(id: number, data: { status?: string; actual_payout?: number }) {
  return request<any>(`/api/v1/bounties/${id}`, { method: "PATCH", body: JSON.stringify(data) });
},
getBountyStats() {
  return request<{ stats: any }>("/api/v1/bounties/stats");
},

// Scheduling
createSchedule(data: { target_id: number; cron_expression: string; playbook?: string }) {
  return request<any>("/api/v1/schedules", { method: "POST", body: JSON.stringify(data) });
},
getSchedules(targetId?: number) {
  const qs = targetId ? `?target_id=${targetId}` : "";
  return request<{ schedules: any[] }>(`/api/v1/schedules${qs}`);
},
updateSchedule(id: number, data: { enabled?: boolean; cron_expression?: string }) {
  return request<any>(`/api/v1/schedules/${id}`, { method: "PATCH", body: JSON.stringify(data) });
},
deleteSchedule(id: number) {
  return request<void>(`/api/v1/schedules/${id}`, { method: "DELETE" });
},

// Intel Enrichment
getApiKeyStatus() {
  return request<{ keys: Record<string, boolean> }>("/api/v1/config/api_keys");
},
updateApiKeys(data: { shodan_api_key?: string; securitytrails_api_key?: string }) {
  return request<{ keys: Record<string, boolean> }>("/api/v1/config/api_keys", { method: "PUT", body: JSON.stringify(data) });
},
enrichTarget(targetId: number) {
  return request<{ target_id: number; enrichment: any[] }>(`/api/v1/targets/${targetId}/enrich`, { method: "POST" });
},

// Playbooks
getPlaybooks() {
  return request<{ playbooks: any[] }>("/api/v1/playbooks");
},
createPlaybook(data: { name: string; description?: string; stages: any[]; concurrency?: any }) {
  return request<any>("/api/v1/playbooks", { method: "POST", body: JSON.stringify(data) });
},
updatePlaybook(id: number, data: any) {
  return request<any>(`/api/v1/playbooks/${id}`, { method: "PATCH", body: JSON.stringify(data) });
},
deletePlaybook(id: number) {
  return request<void>(`/api/v1/playbooks/${id}`, { method: "DELETE" });
},

// Export
exportFindings(targetId: number, format: "json" | "csv" | "markdown" = "json") {
  return request<any>(`/api/v1/targets/${targetId}/export?format=${format}`);
},

// Scope Violations
getScopeViolations(targetId: number) {
  return request<{ violations: any[] }>(`/api/v1/scope_violations?target_id=${targetId}`);
},

// Metrics / Search
search(targetId: number, query: string) {
  return request<{ results: any[] }>(`/api/v1/search?target_id=${targetId}&q=${encodeURIComponent(query)}`);
},
```

**Step 1:** Add all methods
**Step 2:** Commit

---

## Batch 5: Dashboard — New Pages & Components

### Task 22: Split-Pane Worker Console

Side-by-side terminal views for monitoring multiple workers.

**Files:**
- Create: `dashboard/src/components/c2/SplitConsole.tsx`
- Modify: `dashboard/src/app/campaign/c2/page.tsx` — add toggle for split view

**Component structure:**

```tsx
// SplitConsole.tsx — renders 2-4 WorkerFeed panes side by side
interface SplitConsoleProps {
  events: SSEEvent[];
  jobs: JobState[];
}

export default function SplitConsole({ events, jobs }: SplitConsoleProps) {
  const [selectedWorkers, setSelectedWorkers] = useState<string[]>([]);
  // Render 2-column grid with WorkerFeed per selected worker
  // Filter events by container_name match
}
```

**Step 1:** Create component
**Step 2:** Wire into C2 page with a toggle button
**Step 3:** Commit

---

### Task 23: Interactive Attack Graph

Enhance the existing D3 force-directed graph with click-to-expand, severity coloring, and zoom controls.

**Files:**
- Modify: `dashboard/src/components/campaign/AttackGraph.tsx` — add interactivity
- Modify: `dashboard/src/app/campaign/graph/page.tsx` — add filter controls

**Enhancements:**
- Click node → show detail panel (asset info, vulns, ports)
- Color nodes by severity (red=critical, orange=high, yellow=medium, blue=low)
- Mouse wheel zoom + pan
- Filter checkboxes: show/hide by node type (target, asset, vulnerability, port)
- Highlight path from target → asset → vuln on vuln click

**Step 1:** Add zoom/pan with D3 zoom behavior
**Step 2:** Add severity-based coloring
**Step 3:** Add click handler → detail panel
**Step 4:** Add filter controls
**Step 5:** Commit

---

### Task 24: Campaign Timeline (Gantt View)

Visualize when each worker/stage ran, its duration, and findings discovered.

**Files:**
- Create: `dashboard/src/components/c2/CampaignTimeline.tsx`
- Modify: `dashboard/src/app/campaign/c2/page.tsx` — add below WorkerGrid

**Data source:** `job_state` table has `created_at`, `last_seen`, `current_phase`, `status` per worker.

**Component structure:**

```tsx
interface TimelineEntry {
  container: string;
  phase: string;
  status: string;
  start: Date;
  end: Date;
}

// Render horizontal bars per worker, colored by status
// RUNNING=neon-green, COMPLETED=neon-blue, FAILED=danger, PAUSED=neon-orange
```

Use CSS grid or absolute positioning for the Gantt bars. No D3 needed — pure CSS.

**Step 1:** Create component
**Step 2:** Wire into C2 page
**Step 3:** Commit

---

### Task 25: Target Comparison View

Side-by-side diff of two targets' asset inventories.

**Files:**
- Create: `dashboard/src/app/campaign/compare/page.tsx`
- Modify: `dashboard/src/components/layout/IconRail.tsx` — add nav item

**Page structure:**
- Two dropdown selectors (pick target A and target B)
- Fetch assets for both, compute diff (shared, A-only, B-only)
- Display in three-column layout with asset counts and severity summaries

**Step 1:** Create page with target selectors
**Step 2:** Implement diff logic (Set intersection/difference on asset_value)
**Step 3:** Render results
**Step 4:** Add to nav
**Step 5:** Commit

---

### Task 26: Global Search

Full-text search across assets, vulns, observations, and worker logs.

**Files:**
- Modify: `orchestrator/main.py` — add `GET /api/v1/search` endpoint
- Modify: `dashboard/src/components/layout/CommandPalette.tsx` — wire to search API

**Search endpoint:**

```python
@app.get("/api/v1/search")
async def search(
    target_id: int = Query(...),
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(default=50, le=200),
):
    results = []
    async with get_session() as session:
        # Search assets
        asset_stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_value.ilike(f"%{q}%"),
        ).limit(limit)
        for a in (await session.execute(asset_stmt)).scalars():
            results.append({"type": "asset", "id": a.id, "value": a.asset_value, "subtype": a.asset_type})

        # Search vulns
        vuln_stmt = select(Vulnerability).where(
            Vulnerability.target_id == target_id,
            (Vulnerability.title.ilike(f"%{q}%") | Vulnerability.description.ilike(f"%{q}%")),
        ).limit(limit)
        for v in (await session.execute(vuln_stmt)).scalars():
            results.append({"type": "vulnerability", "id": v.id, "value": v.title, "subtype": v.severity})

    return {"query": q, "results": results[:limit]}
```

**CommandPalette update:** When user types in Cmd+K, debounce-call search API and show results in the palette dropdown. Click result → navigate to appropriate page.

**Step 1:** Add search endpoint
**Step 2:** Update CommandPalette to call search API
**Step 3:** Commit

---

### Task 27: Dashboard Onboarding Tour

First-run guided tour using a simple step-based overlay.

**Files:**
- Create: `dashboard/src/components/common/OnboardingTour.tsx`
- Modify: `dashboard/src/stores/ui.ts` — add `hasSeenTour` persisted state
- Modify: `dashboard/src/app/layout.tsx` — render tour on first visit

**Tour steps:**

1. "Welcome to WebAppBH" → point at nav rail
2. "Start a new campaign" → highlight Campaign nav item
3. "Monitor in real-time" → highlight C2 nav item
4. "Review findings" → highlight Vulns nav item
5. "Export reports" → highlight Reports nav item

**Implementation:** Spotlight overlay with tooltip positioned next to each highlighted element via `getBoundingClientRect()`. Store `hasSeenTour: true` in Zustand persist.

**Step 1:** Create component
**Step 2:** Add state to ui.ts
**Step 3:** Wire into layout
**Step 4:** Commit

---

## Batch 6: Dashboard — Intel API Key UI & Playbook Editor

### Task 28: Intel API Key Section in ScopeBuilder

Add a section in Step 0 (Target Intel) of ScopeBuilder for users to enter Shodan and SecurityTrails API keys. Check if keys are already configured via the API.

**Files:**
- Modify: `dashboard/src/components/campaign/ScopeBuilder.tsx` — add API key section

**Changes to Step 0:**

After the "Notes" textarea, add:

```tsx
{/* ---- API Keys for Intel Enrichment ---- */}
<div className="rounded-md border border-border bg-bg-tertiary p-3 space-y-3">
  <span className="section-label">Intel Enrichment API Keys</span>
  <p className="text-xs text-text-muted">
    Optional. Enable passive OSINT enrichment before recon starts.
  </p>

  {/* Show status badges for configured keys */}
  <div className="flex gap-2">
    {Object.entries(apiKeyStatus).map(([key, configured]) => (
      <span key={key} className={`rounded-full px-2 py-0.5 text-xs font-mono ${
        configured ? "bg-neon-green/15 text-neon-green" : "bg-bg-surface text-text-muted"
      }`}>
        {key}: {configured ? "configured" : "not set"}
      </span>
    ))}
  </div>

  <div>
    <label className="section-label mb-1.5 block">Shodan API Key</label>
    <input
      type="password"
      value={shodanKey}
      onChange={(e) => setShodanKey(e.target.value)}
      placeholder={apiKeyStatus.shodan ? "••••••••••••" : "Enter Shodan API key"}
      className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
    />
  </div>

  <div>
    <label className="section-label mb-1.5 block">SecurityTrails API Key</label>
    <input
      type="password"
      value={secTrailsKey}
      onChange={(e) => setSecTrailsKey(e.target.value)}
      placeholder={apiKeyStatus.securitytrails ? "••••••••••••" : "Enter SecurityTrails API key"}
      className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
    />
  </div>
</div>
```

**State additions:**

```tsx
const [shodanKey, setShodanKey] = useState("");
const [secTrailsKey, setSecTrailsKey] = useState("");
const [apiKeyStatus, setApiKeyStatus] = useState<Record<string, boolean>>({ shodan: false, securitytrails: false });

// On mount, check which keys are configured
useEffect(() => {
  api.getApiKeyStatus().then((res) => setApiKeyStatus(res.keys)).catch(() => {});
}, []);
```

**On submit (before creating target):** If keys were entered, save them first:

```tsx
if (shodanKey || secTrailsKey) {
  await api.updateApiKeys({
    ...(shodanKey ? { shodan_api_key: shodanKey } : {}),
    ...(secTrailsKey ? { securitytrails_api_key: secTrailsKey } : {}),
  });
}
```

**Step 1:** Add state and API calls
**Step 2:** Add UI section
**Step 3:** Update submit handler
**Step 4:** Commit

---

### Task 29: Custom Playbook Editor UI

Add a UI-based playbook builder that lets users drag/toggle stages and set per-tool params.

**Files:**
- Create: `dashboard/src/components/campaign/PlaybookEditor.tsx`
- Modify: `dashboard/src/components/campaign/PlaybookSelector.tsx` — add "Create Custom" button

**Component structure:**

```tsx
interface PlaybookEditorProps {
  onSave: (playbook: { name: string; stages: StageConfig[]; concurrency: { heavy: number; light: number } }) => void;
  onCancel: () => void;
  initial?: { name: string; stages: StageConfig[]; concurrency: { heavy: number; light: number } };
}

// Renders:
// 1. Name + description fields
// 2. Stage list with toggle switches (enabled/disabled)
// 3. Tool timeout slider per stage
// 4. Concurrency sliders (heavy/light)
// 5. Save/Cancel buttons
```

**PlaybookSelector change:** Add a "Custom" card at the end of the playbook grid that opens the editor in a modal.

**Step 1:** Create PlaybookEditor component
**Step 2:** Add "Create Custom" to PlaybookSelector
**Step 3:** Wire API calls for CRUD
**Step 4:** Commit

---

### Task 30: Bounty Tracker Dashboard Page

New page for viewing/managing bounty submissions with ROI stats.

**Files:**
- Create: `dashboard/src/app/campaign/bounties/page.tsx`
- Modify: `dashboard/src/components/layout/IconRail.tsx` — add nav item

**Page sections:**
1. **Stats cards** — Total submitted, accepted, paid, total payout (from `/api/v1/bounties/stats`)
2. **Submission table** — List all submissions with status pills, sortable columns
3. **Quick actions** — Update status dropdown, edit payout inline
4. **ROI chart** — Simple bar chart showing payout per target (CSS-based, no chart library)

**Step 1:** Create page
**Step 2:** Add to nav
**Step 3:** Commit

---

### Task 31: Scheduling Dashboard Page

New page for managing scheduled scans.

**Files:**
- Create: `dashboard/src/app/campaign/schedules/page.tsx`
- Modify: `dashboard/src/components/layout/IconRail.tsx` — add nav item

**Page sections:**
1. **Active schedules table** — target, cron, playbook, last_run, next_run, toggle enabled
2. **Create schedule form** — target dropdown, cron expression input, playbook selector

**Step 1:** Create page
**Step 2:** Add to nav
**Step 3:** Commit

---

## Execution Order Summary

| Batch | Tasks | Focus | Dependencies |
|-------|-------|-------|-------------|
| 1 | 1-10 | Backend core: models, API endpoints | None |
| 2 | 11-14 | Performance & reliability | Batch 1 (uses new models) |
| 3 | 15-20 | Operations, DevOps, security | Independent |
| 4 | 21 | Dashboard API client updates | Batch 1 (endpoints must exist) |
| 5 | 22-27 | Dashboard new pages & components | Batch 4 (API client ready) |
| 6 | 28-31 | Dashboard intel UI, playbook editor, bounties | Batch 4+5 |

**Total new files:** ~20
**Total modified files:** ~15
**Estimated commits:** 31

---

## Dependencies to Install

**Python (add to shared/lib_webbh setup.cfg or pyproject.toml):**
- `croniter` — cron expression parsing (Task 4)
- `httpx` — async HTTP client for intel APIs (Task 5)
- `prometheus-client` — metrics (Task 15)

**No new npm packages required** — all dashboard features use existing React/Zustand/Tailwind stack.
