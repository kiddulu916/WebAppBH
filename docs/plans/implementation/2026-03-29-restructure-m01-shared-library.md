# M1: Shared Library & Database Schema Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Update `lib_webbh` with new ORM models, columns, indexes, and priority queue messaging helpers required by the WSTG-aligned restructure.

**Architecture:** Additive schema changes on existing models (Target, Vulnerability, JobState) + three new tables (Campaign, EscalationContext, ChainFinding). New `push_priority_task()` and `listen_priority_queues()` functions in `messaging.py`. Alembic migration for production rollout.

**Tech Stack:** Python 3.10, SQLAlchemy 2.0 (async, mapped_column), asyncpg, redis-py (async), pytest + pytest-asyncio + aiosqlite

**Design docs:** `docs/plans/design/2026-03-29-restructure-10-database-messaging.md`, `docs/plans/design/2026-03-29-restructure-00-overview.md`

---

## Task 1: Campaign Model

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Modify: `tests/conftest.py` (if needed for new model fixture)
- Test: `tests/test_database_campaign.py`

**Step 1: Write the failing test**

```python
# tests/test_database_campaign.py
import pytest
from datetime import datetime, timezone

pytestmark = pytest.mark.anyio


async def test_create_campaign(db_session):
    from lib_webbh.database import Campaign

    campaign = Campaign(
        name="Test Campaign",
        description="Testing the campaign model",
        status="pending",
        scope_config={"in_scope": ["*.target.com"]},
        rate_limit=50,
        has_credentials=False,
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    assert campaign.id is not None
    assert campaign.name == "Test Campaign"
    assert campaign.status == "pending"
    assert campaign.scope_config == {"in_scope": ["*.target.com"]}
    assert campaign.rate_limit == 50
    assert campaign.has_credentials is False
    assert campaign.started_at is None
    assert campaign.completed_at is None
    assert isinstance(campaign.created_at, datetime)


async def test_campaign_defaults(db_session):
    from lib_webbh.database import Campaign

    campaign = Campaign(name="Minimal Campaign")
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    assert campaign.status == "pending"
    assert campaign.rate_limit == 50
    assert campaign.has_credentials is False
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database_campaign.py -v`
Expected: FAIL — `ImportError: cannot import name 'Campaign' from 'lib_webbh.database'`

**Step 3: Write the Campaign model**

Add to `shared/lib_webbh/database.py` after the existing models:

```python
class Campaign(TimestampMixin, Base):
    """Campaign grouping multiple targets for a single engagement."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    scope_config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    rate_limit: Mapped[int] = mapped_column(Integer, default=50)
    has_credentials: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    targets: Mapped[list["Target"]] = relationship(back_populates="campaign")
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database_campaign.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_campaign.py
git commit -m "feat(db): add Campaign model"
```

---

## Task 2: Target Model — Hierarchy & Priority Columns

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Test: `tests/test_database_target_hierarchy.py`

**Step 1: Write the failing test**

```python
# tests/test_database_target_hierarchy.py
import pytest

pytestmark = pytest.mark.anyio


async def test_target_has_campaign_id(db_session):
    from lib_webbh.database import Target, Campaign

    campaign = Campaign(name="Test")
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    target = Target(
        company_name="TestCo",
        base_domain="target.com",
        campaign_id=campaign.id,
        target_type="seed",
        priority=100,
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.campaign_id == campaign.id
    assert target.target_type == "seed"
    assert target.priority == 100
    assert target.wildcard is False
    assert target.wildcard_count is None
    assert target.parent_target_id is None


async def test_target_parent_child_relationship(db_session):
    from lib_webbh.database import Target

    parent = Target(company_name="TestCo", base_domain="target.com", target_type="seed")
    db_session.add(parent)
    await db_session.commit()
    await db_session.refresh(parent)

    child = Target(
        company_name="TestCo",
        base_domain="api.target.com",
        parent_target_id=parent.id,
        target_type="child",
        priority=85,
    )
    db_session.add(child)
    await db_session.commit()
    await db_session.refresh(child)

    assert child.parent_target_id == parent.id
    assert child.target_type == "child"

    # Refresh parent to load children relationship
    await db_session.refresh(parent, ["children"])
    assert len(parent.children) == 1
    assert parent.children[0].base_domain == "api.target.com"


async def test_target_wildcard(db_session):
    from lib_webbh.database import Target

    target = Target(
        company_name="TestCo",
        base_domain="*.target.com",
        wildcard=True,
        wildcard_count=50,
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.wildcard is True
    assert target.wildcard_count == 50


async def test_target_defaults(db_session):
    from lib_webbh.database import Target

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.target_type == "seed"
    assert target.priority == 50
    assert target.wildcard is False
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database_target_hierarchy.py -v`
Expected: FAIL — Target model lacks `campaign_id`, `parent_target_id`, etc.

**Step 3: Add new columns to Target model**

Modify the `Target` class in `shared/lib_webbh/database.py`:

```python
class Target(TimestampMixin, Base):
    """Top-level reconnaissance target (company / domain)."""

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("company_name", "base_domain", name="uq_targets_company_domain"),
        Index("ix_targets_parent", "parent_target_id"),
        Index("ix_targets_campaign", "campaign_id"),
        Index("ix_targets_priority", "priority"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    company_name: Mapped[str] = mapped_column(String(255))
    base_domain: Mapped[str] = mapped_column(String(255))
    target_profile: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_playbook: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Campaign & hierarchy
    campaign_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("campaigns.id"), nullable=True
    )
    parent_target_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("targets.id"), nullable=True
    )
    target_type: Mapped[str] = mapped_column(String(20), default="seed")
    priority: Mapped[int] = mapped_column(Integer, default=50)
    wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    wildcard_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Relationships (existing)
    assets: Mapped[list["Asset"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    identities: Mapped[list["Identity"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    cloud_assets: Mapped[list["CloudAsset"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    jobs: Mapped[list["JobState"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    api_schemas: Mapped[list["ApiSchema"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    mobile_apps: Mapped[list["MobileApp"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    snapshots: Mapped[list["AssetSnapshot"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    bounty_submissions: Mapped[list["BountySubmission"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    scheduled_scans: Mapped[list["ScheduledScan"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    scope_violations: Mapped[list["ScopeViolation"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    # Relationships (new)
    campaign: Mapped[Optional["Campaign"]] = relationship(back_populates="targets")
    parent: Mapped[Optional["Target"]] = relationship(
        remote_side=[id], back_populates="children",
        foreign_keys=[parent_target_id],
    )
    children: Mapped[list["Target"]] = relationship(
        back_populates="parent",
        foreign_keys=[parent_target_id],
    )
```

Note: The `parent` and `children` self-referential relationships require explicit `foreign_keys` to avoid ambiguity.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database_target_hierarchy.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_target_hierarchy.py
git commit -m "feat(db): add campaign_id, parent/child hierarchy, priority columns to Target"
```

---

## Task 3: Vulnerability Model — Section ID & Worker Tracking Columns

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Test: `tests/test_database_vulnerability_ext.py`

**Step 1: Write the failing test**

```python
# tests/test_database_vulnerability_ext.py
import pytest

pytestmark = pytest.mark.anyio


async def test_vulnerability_section_tracking(db_session):
    from lib_webbh.database import Target, Vulnerability

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    vuln = Vulnerability(
        target_id=target.id,
        severity="critical",
        title="SQL Injection in login",
        section_id="4.7.5",
        worker_type="input_validation",
        stage_name="sql_injection",
        vuln_type="sqli",
        confirmed=True,
        false_positive=False,
        evidence={"request": "POST /login", "response_time": 5124},
    )
    db_session.add(vuln)
    await db_session.commit()
    await db_session.refresh(vuln)

    assert vuln.section_id == "4.7.5"
    assert vuln.worker_type == "input_validation"
    assert vuln.stage_name == "sql_injection"
    assert vuln.vuln_type == "sqli"
    assert vuln.confirmed is True
    assert vuln.false_positive is False
    assert vuln.evidence == {"request": "POST /login", "response_time": 5124}


async def test_vulnerability_new_defaults(db_session):
    from lib_webbh.database import Target, Vulnerability

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln = Vulnerability(
        target_id=target.id,
        severity="medium",
        title="Missing HSTS",
    )
    db_session.add(vuln)
    await db_session.commit()
    await db_session.refresh(vuln)

    assert vuln.confirmed is False
    assert vuln.false_positive is False
    assert vuln.section_id is None
    assert vuln.worker_type is None
    assert vuln.evidence is None
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database_vulnerability_ext.py -v`
Expected: FAIL — Vulnerability model lacks `section_id`, `worker_type`, etc.

**Step 3: Add new columns to Vulnerability model**

Modify the `Vulnerability` class in `shared/lib_webbh/database.py`. Add these columns after `source_tool`:

```python
    # WSTG tracking (new)
    section_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    worker_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    stage_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vuln_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

Add new indexes to `__table_args__`:

```python
    __table_args__ = (
        Index("ix_vulns_target_severity", "target_id", "severity"),
        Index("ix_vulns_target_created", "target_id", "created_at"),
        Index("ix_vulns_section", "section_id"),
        Index("ix_vulns_worker", "worker_type"),
        Index("ix_vulns_confirmed", "confirmed"),
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database_vulnerability_ext.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_vulnerability_ext.py
git commit -m "feat(db): add section_id, worker_type, confirmed, evidence columns to Vulnerability"
```

---

## Task 4: JobState Model — Stage Tracking & Skip Columns

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Test: `tests/test_database_jobstate_ext.py`

**Step 1: Write the failing test**

```python
# tests/test_database_jobstate_ext.py
import pytest
from datetime import datetime, timezone

pytestmark = pytest.mark.anyio


async def test_jobstate_new_fields(db_session):
    from lib_webbh.database import Target, JobState

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    job = JobState(
        target_id=target.id,
        container_name="info_gathering",
        status="running",
        current_section_id="4.1.3",
        queued_at=now,
        started_at=now,
    )
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)

    assert job.current_section_id == "4.1.3"
    assert job.queued_at == now
    assert job.started_at == now
    assert job.completed_at is None
    assert job.skipped is False
    assert job.skip_reason is None
    assert job.retry_count == 0


async def test_jobstate_skip(db_session):
    from lib_webbh.database import Target, JobState

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    job = JobState(
        target_id=target.id,
        container_name="identity_mgmt",
        status="complete",
        skipped=True,
        skip_reason="no credentials provided",
    )
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)

    assert job.skipped is True
    assert job.skip_reason == "no credentials provided"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database_jobstate_ext.py -v`
Expected: FAIL — JobState lacks `current_section_id`, `skipped`, etc.

**Step 3: Add new columns to JobState model**

Add to `JobState` class after existing columns:

```python
    # Stage tracking (new)
    current_section_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    queued_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    skipped: Mapped[bool] = mapped_column(Boolean, default=False)
    skip_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
```

Add compound index to `__table_args__`:

```python
    __table_args__ = (
        Index("ix_jobstate_target_status", "target_id", "status"),
        Index("ix_jobstate_container_status", "container_name", "status"),
        Index("ix_jobstate_target_container", "target_id", "container_name"),
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database_jobstate_ext.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_jobstate_ext.py
git commit -m "feat(db): add section tracking, skip, retry columns to JobState"
```

---

## Task 5: EscalationContext Model

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Test: `tests/test_database_escalation.py`

**Step 1: Write the failing test**

```python
# tests/test_database_escalation.py
import pytest

pytestmark = pytest.mark.anyio


async def test_create_escalation_context(db_session):
    from lib_webbh.database import Target, Vulnerability, EscalationContext

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln = Vulnerability(
        target_id=target.id, severity="critical", title="SQLi"
    )
    db_session.add(vuln)
    await db_session.commit()
    await db_session.refresh(vuln)

    esc = EscalationContext(
        target_id=target.id,
        vulnerability_id=vuln.id,
        access_type="admin_panel",
        access_method="SQLi to extract admin session token, replayed cookie",
        session_data="encrypted_session_blob",
        data_exposed="All user PII visible in admin panel",
        severity="critical",
        section_id="4.7.5",
    )
    db_session.add(esc)
    await db_session.commit()
    await db_session.refresh(esc)

    assert esc.id is not None
    assert esc.access_type == "admin_panel"
    assert esc.consumed_by_chain is False
    assert esc.chain_findings is None


async def test_escalation_consumed_by_chain(db_session):
    from lib_webbh.database import Target, Vulnerability, EscalationContext

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln = Vulnerability(target_id=target.id, severity="high", title="IDOR")
    db_session.add(vuln)
    await db_session.commit()

    esc = EscalationContext(
        target_id=target.id,
        vulnerability_id=vuln.id,
        access_type="user_account",
        access_method="IDOR on /api/users/{id}",
        severity="high",
        consumed_by_chain=True,
        chain_findings={"additional_vulns": [101, 102]},
    )
    db_session.add(esc)
    await db_session.commit()
    await db_session.refresh(esc)

    assert esc.consumed_by_chain is True
    assert esc.chain_findings == {"additional_vulns": [101, 102]}
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database_escalation.py -v`
Expected: FAIL — `ImportError: cannot import name 'EscalationContext'`

**Step 3: Write the EscalationContext model**

Add to `shared/lib_webbh/database.py`:

```python
class EscalationContext(TimestampMixin, Base):
    """Records escalated access discovered during testing."""

    __tablename__ = "escalation_contexts"
    __table_args__ = (
        Index("ix_escalation_target", "target_id"),
        Index("ix_escalation_consumed", "consumed_by_chain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    vulnerability_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id"))
    access_type: Mapped[str] = mapped_column(String(100))
    access_method: Mapped[str] = mapped_column(Text)
    session_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_exposed: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20))
    section_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    consumed_by_chain: Mapped[bool] = mapped_column(Boolean, default=False)
    chain_findings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship("Target")
    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability")
```

Also add to Vulnerability's relationships:

```python
    escalation_contexts: Mapped[list["EscalationContext"]] = relationship(
        back_populates="vulnerability"
    )
```

And update EscalationContext's vulnerability relationship to use back_populates:

```python
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="escalation_contexts")
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database_escalation.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_escalation.py
git commit -m "feat(db): add EscalationContext model for escalated access tracking"
```

---

## Task 6: ChainFinding Model

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Test: `tests/test_database_chain.py`

**Step 1: Write the failing test**

```python
# tests/test_database_chain.py
import pytest

pytestmark = pytest.mark.anyio


async def test_create_chain_finding(db_session):
    from lib_webbh.database import (
        Target, Vulnerability, EscalationContext, ChainFinding,
    )

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln1 = Vulnerability(target_id=target.id, severity="high", title="SQLi")
    vuln2 = Vulnerability(target_id=target.id, severity="medium", title="IDOR")
    db_session.add_all([vuln1, vuln2])
    await db_session.commit()
    await db_session.refresh(vuln1)
    await db_session.refresh(vuln2)

    esc = EscalationContext(
        target_id=target.id,
        vulnerability_id=vuln1.id,
        access_type="admin_panel",
        access_method="SQLi token extraction",
        severity="critical",
    )
    db_session.add(esc)
    await db_session.commit()
    await db_session.refresh(esc)

    chain = ChainFinding(
        target_id=target.id,
        escalation_context_id=esc.id,
        chain_description="Step 1: SQLi extracts token. Step 2: IDOR via admin API.",
        entry_vulnerability_id=vuln1.id,
        linked_vulnerability_ids=[vuln1.id, vuln2.id],
        total_impact="Full admin access with data exfiltration",
        severity="critical",
    )
    db_session.add(chain)
    await db_session.commit()
    await db_session.refresh(chain)

    assert chain.id is not None
    assert chain.linked_vulnerability_ids == [vuln1.id, vuln2.id]
    assert chain.severity == "critical"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_database_chain.py -v`
Expected: FAIL — `ImportError: cannot import name 'ChainFinding'`

**Step 3: Write the ChainFinding model**

Add to `shared/lib_webbh/database.py`:

```python
class ChainFinding(TimestampMixin, Base):
    """Vulnerability chain discovered by the chain worker."""

    __tablename__ = "chain_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    escalation_context_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("escalation_contexts.id")
    )
    chain_description: Mapped[str] = mapped_column(Text)
    entry_vulnerability_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id")
    )
    linked_vulnerability_ids: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    total_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20))

    target: Mapped["Target"] = relationship("Target")
    escalation_context: Mapped["EscalationContext"] = relationship("EscalationContext")
    entry_vulnerability: Mapped["Vulnerability"] = relationship(
        "Vulnerability", foreign_keys=[entry_vulnerability_id]
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_database_chain.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_chain.py
git commit -m "feat(db): add ChainFinding model for vulnerability chain tracking"
```

---

## Task 7: Update `__init__.py` Exports

**Files:**
- Modify: `shared/lib_webbh/__init__.py`

**Step 1: Read current exports**

Run: `cat shared/lib_webbh/__init__.py`

**Step 2: Add new model exports**

Add to the existing imports:

```python
from .database import Campaign, EscalationContext, ChainFinding
```

**Step 3: Run all tests to verify nothing broke**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 4: Commit**

```bash
git add shared/lib_webbh/__init__.py
git commit -m "feat(lib): export Campaign, EscalationContext, ChainFinding from lib_webbh"
```

---

## Task 8: Priority Queue — `push_priority_task()`

**Files:**
- Modify: `shared/lib_webbh/messaging.py`
- Test: `tests/test_messaging_priority.py`

**Step 1: Write the failing test**

```python
# tests/test_messaging_priority.py
import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.anyio


async def test_push_priority_task_critical():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-123"

        result = await push_priority_task(
            "config_mgmt_queue",
            {"target_id": 1, "worker": "config_mgmt"},
            priority_score=95,
        )

        mock_push.assert_called_once_with(
            "config_mgmt_queue:critical",
            {"target_id": 1, "worker": "config_mgmt"},
        )
        assert result == "msg-123"


async def test_push_priority_task_high():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-456"
        await push_priority_task("queue", {"data": 1}, priority_score=75)
        mock_push.assert_called_once_with("queue:high", {"data": 1})


async def test_push_priority_task_normal():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-789"
        await push_priority_task("queue", {"data": 1}, priority_score=55)
        mock_push.assert_called_once_with("queue:normal", {"data": 1})


async def test_push_priority_task_low():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg-000"
        await push_priority_task("queue", {"data": 1}, priority_score=30)
        mock_push.assert_called_once_with("queue:low", {"data": 1})


async def test_push_priority_task_boundary_90():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg"
        await push_priority_task("queue", {}, priority_score=90)
        mock_push.assert_called_once_with("queue:critical", {})


async def test_push_priority_task_boundary_70():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg"
        await push_priority_task("queue", {}, priority_score=70)
        mock_push.assert_called_once_with("queue:high", {})


async def test_push_priority_task_boundary_50():
    from lib_webbh.messaging import push_priority_task

    with patch("lib_webbh.messaging.push_task", new_callable=AsyncMock) as mock_push:
        mock_push.return_value = "msg"
        await push_priority_task("queue", {}, priority_score=50)
        mock_push.assert_called_once_with("queue:normal", {})
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_messaging_priority.py -v`
Expected: FAIL — `ImportError: cannot import name 'push_priority_task'`

**Step 3: Write the function**

Add to `shared/lib_webbh/messaging.py`:

```python
async def push_priority_task(
    queue_prefix: str,
    data: dict[str, Any],
    priority_score: int,
) -> str:
    """Push a task to the appropriate priority-tiered stream.

    Priority tiers:
        >= 90 → :critical
        >= 70 → :high
        >= 50 → :normal
        <  50 → :low
    """
    if priority_score >= 90:
        tier = "critical"
    elif priority_score >= 70:
        tier = "high"
    elif priority_score >= 50:
        tier = "normal"
    else:
        tier = "low"

    return await push_task(f"{queue_prefix}:{tier}", data)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_messaging_priority.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/messaging.py tests/test_messaging_priority.py
git commit -m "feat(messaging): add push_priority_task() for priority-tiered Redis streams"
```

---

## Task 9: Priority Queue — `listen_priority_queues()`

**Files:**
- Modify: `shared/lib_webbh/messaging.py`
- Test: `tests/test_messaging_listen_priority.py`

**Step 1: Write the failing test**

```python
# tests/test_messaging_listen_priority.py
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


async def test_listen_priority_queues_yields_messages():
    from lib_webbh.messaging import listen_priority_queues

    # Simulate: 1 critical message, then StopAsyncIteration
    call_count = 0

    async def mock_xreadgroup(groupname, consumername, streams, count, block):
        nonlocal call_count
        call_count += 1
        stream_name = list(streams.keys())[0]
        if call_count == 1 and stream_name.endswith(":critical"):
            return [(stream_name, [("msg-1", {"payload": '{"target_id": 1}'})])]
        return []

    mock_redis = AsyncMock()
    mock_redis.xreadgroup = mock_xreadgroup
    mock_redis.xgroup_create = AsyncMock()

    messages = []
    with patch("lib_webbh.messaging.get_redis", return_value=mock_redis):
        async for msg in listen_priority_queues(
            "config_mgmt_queue", "test_group", "test_consumer"
        ):
            messages.append(msg)
            if len(messages) >= 1:
                break

    assert len(messages) == 1
    assert messages[0]["payload"]["target_id"] == 1
    assert messages[0]["stream"].endswith(":critical")


async def test_listen_priority_queues_order():
    """Critical messages are yielded before low messages."""
    from lib_webbh.messaging import listen_priority_queues

    async def mock_xreadgroup(groupname, consumername, streams, count, block):
        stream_name = list(streams.keys())[0]
        if stream_name.endswith(":critical"):
            return [(stream_name, [("c1", {"payload": '{"p": "critical"}'})])]
        elif stream_name.endswith(":high"):
            return [(stream_name, [("h1", {"payload": '{"p": "high"}'})])]
        elif stream_name.endswith(":normal"):
            return [(stream_name, [("n1", {"payload": '{"p": "normal"}'})])]
        elif stream_name.endswith(":low"):
            return [(stream_name, [("l1", {"payload": '{"p": "low"}'})])]
        return []

    mock_redis = AsyncMock()
    mock_redis.xreadgroup = mock_xreadgroup
    mock_redis.xgroup_create = AsyncMock()

    messages = []
    with patch("lib_webbh.messaging.get_redis", return_value=mock_redis):
        async for msg in listen_priority_queues("q", "g", "c"):
            messages.append(msg)
            if len(messages) >= 4:
                break

    # Critical should come first, then high, normal, low
    priorities = [m["payload"]["p"] for m in messages]
    assert priorities == ["critical", "high", "normal", "low"]
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_messaging_listen_priority.py -v`
Expected: FAIL — `ImportError: cannot import name 'listen_priority_queues'`

**Step 3: Write the function**

Add to `shared/lib_webbh/messaging.py`:

```python
import json
from typing import AsyncIterator


async def listen_priority_queues(
    queue_prefix: str,
    group: str,
    consumer: str,
) -> AsyncIterator[dict[str, Any]]:
    """Read from priority-tiered queues with weighted consumption.

    Yields dicts with keys: stream, msg_id, payload.
    Higher-priority tiers are consumed first each cycle.
    """
    r = get_redis()
    tier_config = [
        ("critical", 5),
        ("high", 3),
        ("normal", 2),
        ("low", 1),
    ]

    # Ensure consumer groups exist
    for tier_name, _ in tier_config:
        stream_name = f"{queue_prefix}:{tier_name}"
        try:
            await r.xgroup_create(stream_name, group, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    while True:
        yielded_any = False

        for tier_name, batch_size in tier_config:
            stream_name = f"{queue_prefix}:{tier_name}"
            messages = await r.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={stream_name: ">"},
                count=batch_size,
                block=100,
            )
            if not messages:
                continue
            for s_name, stream_messages in messages:
                for msg_id, fields in stream_messages:
                    payload = json.loads(fields["payload"])
                    yielded_any = True
                    yield {
                        "stream": s_name,
                        "msg_id": msg_id,
                        "payload": payload,
                    }

        if not yielded_any:
            await asyncio.sleep(1)
```

Also add `import asyncio` to the top of messaging.py if not already present.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_messaging_listen_priority.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/messaging.py tests/test_messaging_listen_priority.py
git commit -m "feat(messaging): add listen_priority_queues() for weighted priority consumption"
```

---

## Task 10: Update messaging.py exports

**Files:**
- Modify: `shared/lib_webbh/__init__.py`

**Step 1: Add new function exports**

```python
from .messaging import push_priority_task, listen_priority_queues
```

**Step 2: Run all tests**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 3: Commit**

```bash
git add shared/lib_webbh/__init__.py
git commit -m "feat(lib): export push_priority_task and listen_priority_queues"
```

---

## Task 11: Full Regression Test

**Step 1: Run the complete test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS, including pre-existing tests

**Step 2: Verify models can be imported cleanly**

```python
python -c "from lib_webbh import Campaign, EscalationContext, ChainFinding, push_priority_task, listen_priority_queues; print('All imports OK')"
```

Expected: `All imports OK`

**Step 3: Commit (if any fixups needed)**

```bash
git add -A
git commit -m "fix(m1): regression fixups after schema additions"
```

Only commit if fixups were needed. If all tests passed clean, skip this step.
